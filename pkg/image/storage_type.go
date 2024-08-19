package image

const (
	// StorageTypeDockerFS is the storage type for docker rootfs images.
	StorageTypeDockerFS = "docker-rootfs"
	// StorageTypeDockerRootfs is the storage type for remote registry images.
	StorageTypeRemote = "remote"
)

// AllStorageTypes returns all storage types supported.
func AllStorageTypes() []string {
	return []string{
		StorageTypeDockerFS,
		StorageTypeRemote,
	}
}
