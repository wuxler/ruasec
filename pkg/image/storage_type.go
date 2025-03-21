package image

const (
	// StorageTypeDockerFS is the storage type for docker rootfs images.
	StorageTypeDockerFS = "docker-rootfs"
	// StorageTypeDockerArchive is the storage type for docker archive images.
	StorageTypeDockerArchive = "docker-archive"
	// StorageTypeDockerDaemon is the storage type for docker daemon images.
	StorageTypeDockerDaemon = "docker-daemon"
	// StorageTypeDockerRootfs is the storage type for remote registry images.
	StorageTypeRemote = "remote"
)

// AllStorageTypes returns all storage types supported.
func AllStorageTypes() []string {
	return []string{
		StorageTypeDockerFS,
		StorageTypeDockerArchive,
		StorageTypeDockerDaemon,
		StorageTypeRemote,
	}
}
