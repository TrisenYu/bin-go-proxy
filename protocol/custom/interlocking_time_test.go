package protocol

import (
	"testing"
)

// TODO: check others.

func TestTimeStampSub(t *testing.T) {
	// Judge by observing and comparing
	now := []byte(`2024-10-09 11:59:58.233666`)
	jiffy := []byte(`2024-10-09 23:59:59.315999`)
	TimeStampMinus(jiffy, now)

	now = []byte(`2024-10-09 23:58:59.233666`)
	jiffy = []byte(`2024-10-09 23:59:00.315999`)
	TimeStampMinus(jiffy, now)

	now = []byte(`2024-10-09 22:59:59.233666`)
	jiffy = []byte(`2024-10-09 23:00:00.315999`)
	TimeStampMinus(jiffy, now)

	now = []byte(`2024-10-09 23:59:59.233666`)
	jiffy = []byte(`2024-10-10 00:00:00.315999`)
	TimeStampMinus(jiffy, now)

	now = []byte(`2024-02-29 23:59:59.233666`)
	jiffy = []byte(`2024-03-01 00:00:00.315999`)
	TimeStampMinus(jiffy, now)

	now = []byte(`2024-12-31 23:59:59.233666`)
	jiffy = []byte(`2025-01-01 00:00:00.315999`)
	TimeStampMinus(jiffy, now)
}
