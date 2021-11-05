package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	gname "github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	metadataLabel = "io.buildpacks.lifecycle.metadata"
	appLabel      = "io.buildpacks.app.sbom"
	baseLabel     = "io.buildpacks.base.sbom"
)

func main() {
	if err := run(os.Args[1], "."); err != nil {
		log.Fatalf("Error: %s", err)
	}
}

func run(image, dir string) error {
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
	var appDigest, baseDigest string
	if cf.Config.Labels != nil {
		appDigest = cf.Config.Labels[appLabel]
		baseDigest = cf.Config.Labels[baseLabel]
		if appDigest == "" {
			var md struct {
				BOM struct {
					SHA string
				}
			}
			if err := json.Unmarshal([]byte(cf.Config.Labels[metadataLabel]), &md); err != nil {
				return err
			}
			appDigest = md.BOM.SHA
		}
	}
	if err := writeLayer(img, appDigest, dir, "app", "/layers/sbom"); err != nil {
		return err
	}
	if err := writeLayer(img, baseDigest, dir, "base", "/cnb/sbom"); err != nil {
		return err
	}
	return nil
}

func writeLayer(img v1.Image, digest, dir, prefix, strip string) error {
	hash, err := v1.NewHash(digest)
	if err != nil {
		return err
	}
	appLayer, err := img.LayerByDigest(hash)
	if err != nil {
		return err
	}
	tar, err := appLayer.Uncompressed()
	if err != nil {
		return err
	}
	defer tar.Close()
	return untarSBOMs(tar, dir, prefix, strip)
}

func untarSBOMs(r io.Reader, dir, prefix, strip string) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(header.Name, strip) {
			continue
		}
		s := strings.TrimPrefix(strings.TrimPrefix(header.Name, strip), "/")
		name := prefix + "." + strings.Join(strings.Split(s, "/"), ".")
		size, err := writeFile(filepath.Join(dir, name), tr)
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
