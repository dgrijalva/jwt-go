package jwt

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
)

var (
	// CompressionNone does not perform any data compression/decompression
	CompressionNone CompressionMethod
	// CompressionGzip compresses the claims part of the JWT with gzip algorithm
	CompressionGzip CompressionMethod
)

var (
	compressionMethods map[string]CompressionMethod
)

// CompressionMethod is an interface used to compress/decompress the Claims part of the JWT
type CompressionMethod interface {
	// Alg returns the name of the compression algorithm. It is saved in the token header
	Alg() string
	// Compress takes uncompressed data, and returns the compression result`
	Compress(data []byte) ([]byte, error)
	// Decompress takes compressed data and returns uncompressed version
	Decompress(data []byte) ([]byte, error)
}

type compressionGzip struct{}

type compressionNone struct{}

func (c *compressionGzip) Alg() string {
	return "gzip"
}

func (c *compressionGzip) Compress(data []byte) ([]byte, error) {
	var buffer = &bytes.Buffer{}
	var writer = gzip.NewWriter(buffer)

	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return nil, err
	}

	writer.Close()
	return buffer.Bytes(), nil
}

func (c *compressionGzip) Decompress(data []byte) ([]byte, error) {
	var buffer = bytes.NewBuffer(data)
	var reader, err = gzip.NewReader(buffer)
	defer reader.Close()
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(reader)
}

func (c *compressionNone) Alg() string {
	return "none"
}

func (c *compressionNone) Compress(data []byte) ([]byte, error) {
	return data, nil
}

func (c *compressionNone) Decompress(data []byte) ([]byte, error) {
	return data, nil
}

// RegisterCompressionMethod adds support for additional compression method in the runtime.
// The name value is saved in the token header and later used to retrieve the method interface
// used to decompress the header
func RegisterCompressionMethod(name string, method CompressionMethod) {
	compressionMethods[name] = method
}

func getCompressionMethod(alg interface{}) (CompressionMethod, error) {
	var algString, ok = alg.(string)
	if ok == false || len(algString) == 0 {
		return compressionMethods["none"], nil
	}

	var method = compressionMethods[algString]
	if method == nil {
		return nil, fmt.Errorf("Compression method %s not registered", alg)
	}

	return method, nil
}

func init() {
	CompressionNone = &compressionNone{}
	CompressionGzip = &compressionGzip{}

	compressionMethods = make(map[string]CompressionMethod)
	compressionMethods["none"] = CompressionNone
	compressionMethods["gzip"] = CompressionGzip
}
