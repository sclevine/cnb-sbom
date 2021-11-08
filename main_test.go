package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	gname "github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const testImage = "sclevine/sbom-test-app"

func TestSBoM(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	in := filepath.Join(dir, "in")
	out := filepath.Join(dir, "base."+getDigestHex(t, testImage)[:8]+".test.json")

	if err := ioutil.WriteFile(in, []byte("test"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := addBaseSBoM(testImage, in, ".test.json"); err != nil {
		t.Fatal(err)
	}
	if err := getSBoM(testImage, dir); err != nil {
		// TODO: test with app SBoM
		if !strings.Contains(err.Error(), "could not retrieve app SBoM: cannot parse hash") {
			t.Fatal(err)
		}
	}
	sbom, err := ioutil.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if tt := string(sbom); tt != "test" {
		t.Fatalf("found: %s, expected test string", tt)
	}
}

func getDigestHex(t *testing.T, image string) string {
	ref, err := gname.ParseReference(image, gname.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest.Hex
}
