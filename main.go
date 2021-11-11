package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	gname "github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

const (
	metadataLabel = "io.buildpacks.lifecycle.metadata"
	appLabel      = "io.buildpacks.app.sbom"
	baseLabel     = "io.buildpacks.base.sbom"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" {
		log.Fatalf(`Usage: %s [ "attach-base" | "get" ] ...`, os.Args[0])
	}
	switch os.Args[1] {
	case "attach-base":
		if len(os.Args) != 5 {
			log.Fatalf("Usage: %s attach-base [image] [path] [ext]", os.Args[0])
		}
		if err := addBaseSBoM(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			log.Fatalf("Error: %s", err)
		}
	case "get":
		if len(os.Args) != 3 {
			log.Fatalf("Usage: %s get [image]", os.Args[0])
		}
		if err := getSBoM(os.Args[2], "."); err != nil {
			log.Fatalf("Error: %s", err)
		}
	default:
		log.Fatalf("Error: invalid command `%s'", os.Args[1])
	}

}

func addBaseSBoM(image, filepath, ext string) error {
	ref, err := gname.ParseReference(image, gname.WeakValidation)
	if err != nil {
		return err
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return err
	}
	digest, err := img.Digest()
	if err != nil {
		return err
	}
	dstPath := path.Join("/cnb/sbom", digest.Hex[:8]+"."+strings.TrimPrefix(ext, "."))
	layer, err := createLayer(filepath, dstPath)
	if err != nil {
		return err
	}
	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return err
	}
	diffID, err := layer.DiffID()
	if err != nil {
		return err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return err
	}
	if cf.Config.Labels == nil {
		cf.Config.Labels = make(map[string]string, 1)
	}
	cf.Config.Labels[baseLabel] = diffID.String()
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		return err
	}
	if err := remote.Write(ref, img, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return err
	}
	newDigest, err := img.Digest()
	if err != nil {
		return err
	}
	fmt.Printf("Old digest: %s\n", digest)
	fmt.Printf("New digest: %s\n", newDigest)
	return nil
}

func createLayer(fromPath, toPath string) (v1.Layer, error) {
	return tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		f, err := os.Open(fromPath)
		if err != nil {
			return nil, err
		}
		fd, err := f.Stat()
		if err != nil {
			return nil, err
		}
		return tarFile(f, toPath, fd.Size()), nil
	})
}

func tarFile(r io.ReadCloser, name string, size int64) io.ReadCloser {
	out, w := io.Pipe()
	go func() {
		defer r.Close()
		defer w.Close() // always nil + never overrides
		tw := tar.NewWriter(w)

		// are docker layers ustar or gnu tar?
		header := &tar.Header{
			Name: name,
			Size: size,
			Mode: 0600,
		}

		if err := tw.WriteHeader(header); err != nil {
			w.CloseWithError(err)
			return
		}
		if _, err := io.Copy(tw, r); err != nil {
			w.CloseWithError(err)
			return
		}
		if err := tw.Close(); err != nil {
			w.CloseWithError(err)
			return
		}
	}()
	return out
}

func getSBoM(image, dir string) error {
	ref, err := gname.ParseReference(image, gname.WeakValidation)
	if err != nil {
		return err
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return err
	}
	var appDiffID, baseDiffID string
	if cf.Config.Labels != nil {
		appDiffID = cf.Config.Labels[appLabel]
		baseDiffID = cf.Config.Labels[baseLabel]
		if appDiffID == "" {
			var md struct {
				SBOM struct {
					SHA string
				}
				BOM struct {
					SHA string
				}
			}
			if err := json.Unmarshal([]byte(cf.Config.Labels[metadataLabel]), &md); err != nil {
				return err
			}
			if appDiffID = md.SBOM.SHA; appDiffID == "" {
				appDiffID = md.BOM.SHA
			}
			
		}
	}
	if err := extractLayer(img, baseDiffID, dir, "/cnb/sbom", "base"); err != nil {
		return fmt.Errorf("could not retrieve base image SBoM: %w", err)
	}
	if err := extractLayer(img, appDiffID, dir, "/layers/sbom", "app"); err != nil {
		return fmt.Errorf("could not retrieve app SBoM: %w", err)
	}
	return nil
}

func extractLayer(img v1.Image, diffID, toDir, fromDir, prefix string) error {
	hash, err := v1.NewHash(diffID)
	if err != nil {
		return err
	}
	appLayer, err := img.LayerByDiffID(hash)
	if err != nil {
		return err
	}
	tar, err := appLayer.Uncompressed()
	if err != nil {
		return err
	}
	defer tar.Close()
	return untarSBOMs(tar, toDir, fromDir, prefix)
}

func untarSBOMs(r io.Reader, toDir, fromDir, prefix string) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg ||
			!strings.HasPrefix(header.Name, fromDir) {
			continue
		}
		s := strings.TrimPrefix(strings.TrimPrefix(header.Name, fromDir), "/")
		name := prefix + "." + strings.Join(strings.Split(s, "/"), ".")
		size, err := writeFile(filepath.Join(toDir, name), tr)
		if err != nil {
			return err
		}
		if size != header.Size {
			return errors.New("invalid tar: size mismatch")
		}
	}
	return nil
}

func writeFile(name string, r io.Reader) (n int64, err error) {
	f, err := os.Create(name)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(f, r)
}
