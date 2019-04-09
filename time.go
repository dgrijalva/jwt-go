package jwt

import (
	"encoding/json"
	"math"
	"reflect"
	"time"
)

const TimePrecision = time.Microsecond

type Time struct {
	time.Time
}

func NewTime(t float64) *Time {
	return At(time.Unix(int64(t), int64((t-math.Floor(t))*float64(time.Second))))
}

func Now() *Time {
	return At(TimeFunc())
}

func At(at time.Time) *Time {
	return &Time{at.Truncate(TimePrecision)}
}

func ParseTime(value interface{}) (*Time, error) {
	switch v := value.(type) {
	case int64:
		return NewTime(float64(v)), nil
	case float64:
		return NewTime(v), nil
	case json.Number:
		vv, err := v.Float64()
		if err != nil {
			return nil, err
		}
		return NewTime(vv), nil
	case nil:
		return nil, nil
	default:
		return nil, &json.UnsupportedTypeError{Type: reflect.TypeOf(v)}
	}
}

// UnmarshalJSON implements the json package's Unmarshaler interface
func (t *Time) UnmarshalJSON(data []byte) error {
	var value json.Number
	err := json.Unmarshal(data, &value)
	if err != nil {
		return err
	}
	v, err := ParseTime(value)
	*t = *v
	return err
}

func (t *Time) MarshalJSON() ([]byte, error) {
	f := float64(t.Truncate(TimePrecision).UnixNano()) / float64(time.Second)
	return json.Marshal(f)
}
