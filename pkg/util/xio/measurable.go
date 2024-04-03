package xio

import (
	"io"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
)

var (
	_ MeasurableWriter = (*measurableWriter)(nil)
	_ MeasurableReader = (*measurableReader)(nil)
)

// Measurable is the interface to measure the rate to read/write.
type Measurable interface {
	// BytesPer returns the bytes per period of read/write
	BytesPer(period time.Duration) float64
	// Total returns the total count bytes that already read/write to.
	Total() int64
}

type MeasurableWriter interface {
	io.Writer
	Measurable
}

type MeasurableReader interface {
	io.Reader
	Measurable
}

// NewMeasuredWriter wraps a writer.
func NewMeasuredWriter(w io.Writer) MeasurableWriter {
	return &measurableWriter{wrap: w, rate: newRateCounter()}
}

// measurableWriter wraps a writer and tracks how many bytes are written to it.
type measurableWriter struct {
	wrap io.Writer
	rate *rateCounter
}

// BytesPer tells the rate per period at which bytes were written since last
// measurement.
func (m *measurableWriter) BytesPer(period time.Duration) float64 {
	return m.rate.Rate(period)
}

// Total number of bytes that have been written.
func (m *measurableWriter) Total() int64 {
	return m.rate.Total()
}

func (m *measurableWriter) Write(b []byte) (n int, err error) {
	n, err = m.wrap.Write(b)
	m.rate.Add(n)
	return n, err
}

// NewMeasuredReader wraps a reader.
func NewMeasuredReader(r io.Reader) MeasurableReader {
	return &measurableReader{wrap: r, rate: newRateCounter()}
}

// measurableReader wraps a reader and tracks how many bytes are read to it.
type measurableReader struct {
	wrap io.Reader
	rate *rateCounter
}

// BytesPer tells the rate per period at which bytes were read since last
// measurement.
func (m *measurableReader) BytesPer(perPeriod time.Duration) float64 {
	return m.rate.Rate(perPeriod)
}

// Total number of bytes that have been read.
func (m *measurableReader) Total() int64 {
	return m.rate.Total()
}

func (m *measurableReader) Read(b []byte) (n int, err error) {
	n, err = m.wrap.Read(b)
	m.rate.Add(n)
	return n, err
}

// newRateCounter returns a new rate counter
func newRateCounter() *rateCounter {
	return newCounter(clock.New())
}

func newCounter(clk clock.Clock) *rateCounter {
	return &rateCounter{
		time: clk,
	}
}

type rateCounter struct {
	sync.RWMutex
	time clock.Clock

	count     int64
	lastCount int64
	lastCheck time.Time
}

func (c *rateCounter) Add(n int) {
	c.Lock()
	defer c.Unlock()

	c.count += int64(n)
	if c.lastCheck.IsZero() {
		c.lastCheck = c.time.Now()
	}
}

func (c *rateCounter) Total() int64 {
	c.RLock()
	defer c.RUnlock()
	return c.count
}

func (c *rateCounter) Rate(period time.Duration) float64 {
	c.Lock()
	defer c.Unlock()

	now := c.time.Now()
	between := now.Sub(c.lastCheck)
	changed := c.count - c.lastCount
	rate := float64(changed*int64(period)) / float64(between)

	c.lastCount = c.count
	c.lastCheck = now
	return rate
}
