package mongodb

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
)

type bsonRaw = bson.Raw

var objstoreNotFound = objstore.ErrNotFound

func bsonD(k string, v any) bson.D { return bson.D{{Key: k, Value: v}} }

// tool finds a MongoDB program: ROWSAFE_MONGODB_BIN_DIR, then PATH, then
// /usr/bin.
func tool(name string) (string, error) {
	if dir := os.Getenv("ROWSAFE_MONGODB_BIN_DIR"); dir != "" {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			return "", errors.New(name + " not found in ROWSAFE_MONGODB_BIN_DIR (" + dir + ")")
		}
		return p, nil
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/bin", "/usr/local/bin"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New(name + " is not installed")
}

// checkTools makes sure the MongoDB Database Tools are installed.
func checkTools(env agent.EngineEnv) error {
	for _, t := range []string{"mongodump", "mongorestore"} {
		if _, err := tool(t); err != nil {
			return errors.New("the MongoDB Database Tools (mongodump, mongorestore) aren't installed on this server: " +
				"run the Rowsafe installer again, it installs them from MongoDB's own repository")
		}
	}
	return nil
}

func freeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}

func dirSize(root string) int64 {
	var n int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			n += info.Size()
		}
		return nil
	})
	return n
}

// diskUsage is the size and free space of path's filesystem.
func diskUsage(path string) (total, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return int64(uint64(st.Blocks) * uint64(st.Bsize)), int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}
