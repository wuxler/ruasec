package rootfs

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/go-digest/digestset"
	"github.com/samber/lo"

	"github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/xlog"
)

type rawRepositoriesJSON struct {
	Repositories map[string]map[string]digest.Digest `json:"Repositories"`
}

func newNameDB(root pathspec.DriverRoot) *nameDB {
	return &nameDB{
		DriverRoot: root,
		raw: rawRepositoriesJSON{
			Repositories: make(map[string]map[string]digest.Digest),
		},
		normalized: make(map[string]map[string]digest.Digest),
		refsByID:   make(map[digest.Digest]map[string]name.Reference),
		idset:      digestset.NewSet(),
	}
}

type nameDB struct {
	DriverRoot pathspec.DriverRoot

	// cached value

	// Maps by: repository name => image name => image id
	raw rawRepositoriesJSON
	// Maps by: normalized repository name => normalized image name => image id
	normalized map[string]map[string]digest.Digest
	// Maps by: image id => normalized image name => name.Reference
	refsByID map[digest.Digest]map[string]name.Reference
	// all image id set
	idset *digestset.Set
}

// ReferencesByImageID returns all references for the given ImageID.
func (db *nameDB) ReferencesByImageID(id digest.Digest) []name.Reference {
	// Convert the internal map to an array for two reasons:
	// 1) We must not return a mutable
	// 2) It would be ugly to expose the extraneous map keys to callers.
	refs := lo.Values(db.refsByID[id])
	slices.SortStableFunc(refs, func(a, b name.Reference) int {
		return cmp.Compare(a.String(), b.String())
	})
	return refs
}

// LookupImageID returns the image ID for the given string.
// If the string is a digest, it is returned as-is when found image exists.
// If the string is a image name, it is used to search image id.
// If not found, it will reload the data and try to lookup again.
func (db *nameDB) LookupImageID(ctx context.Context, s string) (digest.Digest, error) {
	id, err := db.lookupImageID(ctx, s)
	if err == nil {
		return id, nil
	}
	// try to reload and lookup agiain
	if id == "" {
		if err := db.reload(ctx); err != nil {
			return "", err
		}
	}
	return db.lookupImageID(ctx, s)
}

func (db *nameDB) lookupImageID(_ context.Context, s string) (digest.Digest, error) {
	var id digest.Digest
	if parsed, err := digest.Parse(s); err == nil {
		id = parsed
	} else if parsed, err := digest.Parse("sha256:" + s); err == nil {
		id = parsed
	} else if found, err := db.idset.Lookup(s); err == nil {
		id = found
	}
	if id != "" {
		// try to find the records with the image id
		refs := db.ReferencesByImageID(id)
		if len(refs) > 0 {
			return id, nil
		}
	}

	// try to find the records with the image name
	ref, err := name.NewReference(s)
	if err != nil {
		return "", fmt.Errorf("invalid reference %s", s)
	}
	return db.getImageIDByReference(ref)
}

func (db *nameDB) reload(ctx context.Context) error {
	rc, err := os.Open(db.DriverRoot.RepositoryJSONFile())
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(rc)

	if err := json.NewDecoder(rc).Decode(&db.raw); err != nil {
		return err
	}

	normalized := make(map[string]map[string]digest.Digest)
	refsByID := make(map[digest.Digest]map[string]name.Reference)
	idset := digestset.NewSet()

	for rawRepoName, repo := range db.raw.Repositories {
		repoName, err := name.NewRepository(rawRepoName)
		if err != nil {
			xlog.C(ctx).Warnf("skip, unable to parse repository name %q: %s", rawRepoName, err)
			continue
		}

		for imageName, imageID := range repo {
			ref, err := name.NewReference(imageName)
			if err != nil {
				xlog.C(ctx).Warnf("skip, unable to parse reference %q: %s", imageName, err)
				continue
			}
			normalizedRefName := ref.String()
			normalizedRepoName := repoName.String()

			if normalized[normalizedRepoName] == nil {
				normalized[normalizedRepoName] = make(map[string]digest.Digest)
			}
			normalized[normalizedRepoName][normalizedRefName] = imageID

			if refsByID[imageID] == nil {
				refsByID[imageID] = make(map[string]name.Reference)
			}
			refsByID[imageID][normalizedRefName] = ref

			if err := idset.Add(imageID); err != nil {
				return err
			}
		}
	}

	db.normalized = normalized
	db.refsByID = refsByID
	db.idset = idset
	return nil
}

// getImageIDByReference returns the ImageID for the given reference.
func (db *nameDB) getImageIDByReference(ref name.Reference) (digest.Digest, error) {
	var err error
	if digested, ok := name.IsDigested(ref); ok {
		// If reference contains both tag and digest, only lookup by digest as it takes
		// precedence over tag, until tag/digest combos are stored.
		if _, ok := name.IsTagged(ref); ok {
			ref, err = name.WithDigest(ref.Repository(), digested.Digest())
			if err != nil {
				return "", err
			}
		}
	} else {
		if _, ok := name.IsTagged(ref); !ok {
			return "", errors.New("input reference must be either a digest or a tag")
		}
	}

	repoName := ref.Repository().String()
	repo, ok := db.normalized[repoName]
	if !ok || repo == nil {
		return "", fmt.Errorf("no such repository %q", repoName)
	}

	refName := ref.String()
	id, ok := repo[refName]
	if !ok || id == "" {
		return "", fmt.Errorf("no such image %q", refName)
	}

	return id, nil
}
