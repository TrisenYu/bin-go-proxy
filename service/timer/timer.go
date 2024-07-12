package timer

import (
	"context"
	"time"
)

func TimeoutCtx(ctx context.Context, cancel context.CancelFunc, ok_ch chan bool, expiration time.Time) bool {
	defer cancel()
	select {
	case <-ctx.Done():
		return true
	case a := <-ok_ch:
		return !a
	}
}

func TimeoutStruct(expired time.Duration, ok_ch chan bool) bool {
	timer := time.NewTimer(expired)
	select {
	case <-timer.C:
		return true
	case a := <-ok_ch:
		if a {
			timer.Stop()
			timer.Reset(expired)
		}
		return !a
	}
}
