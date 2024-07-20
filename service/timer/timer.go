package timer

import (
	"context"
	"log"
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
	// bad implementation.
	// late ok can not be well identified and tackled.

	select {
	case <-timer.C:
		log.Println(`real-timeout: `, cap(ok_ch), len(ok_ch))
		return true
	case a := <-ok_ch:
		return !a
	}
}
