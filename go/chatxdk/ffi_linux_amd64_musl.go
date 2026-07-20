//go:build linux && amd64 && musl

package chatxdk

/*
#cgo LDFLAGS: -L${SRCDIR}/libs/linux_amd64_musl -lchat_xdk_go -lm -ldl -lpthread
*/
import "C"
