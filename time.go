package jwt

import (
	"sync/atomic"
	"time"

	"github.com/beevik/ntp"
)

var ntpServer = "time.google.com"

type Time struct {
	lastCheck time.Time
	ntpOffset int64
}

func NewTime() *Time {
	t := Time{}
	t.syncNTP()
	return &t
}

func (c *Time) Now() time.Time {
	now := time.Now().Add(c.timeOffset())
	if now.After(c.lastCheck.Add(1 * time.Hour)) {
		c.syncNTP()
		now = time.Now().Add(c.timeOffset())
	}
	return now
}

func (c *Time) timeOffset() time.Duration {
	return time.Duration(atomic.LoadInt64(&c.ntpOffset))
}

func (c *Time) syncNTP() error {
	response, err := ntp.Query(ntpServer)
	if err != nil {
		return err
	}

	atomic.StoreInt64(&c.ntpOffset, int64(response.ClockOffset))
	c.lastCheck = time.Now().Add(c.timeOffset())

	return nil
}
