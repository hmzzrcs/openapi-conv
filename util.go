package openapi_conv

import openapi3 "github.com/hmzzrcs/go-openapi"

func convMap[K comparable, V any, D any](src map[K]V, convF func(v V) D) map[K]D {
	if src == nil {
		return nil
	}
	newMap := make(map[K]D)
	for k, v := range src {
		newMap[k] = convF(v)
	}
	return newMap
}

func convArray[V any, D any](src []V, convF func(V) D) []D {
	if src == nil {
		return nil
	}
	newArr := make([]D, 0, len(src))
	for _, v := range src {
		newArr = append(newArr, convF(v))
	}
	return newArr
}

func CopyExtensions[D openapi3.IExtensions](d D, s map[string]interface{}) D {
	if s == nil {
		return d
	}
	for k, v := range s {
		d.AddExtensions(k, v)
	}
	return d
}
