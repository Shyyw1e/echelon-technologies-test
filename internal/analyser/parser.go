package analyser

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

func ParseConfig(data []byte) (map[string]any, error) {
	var root any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse yaml/json config: %w", err)
	}

	normalized := normalize(root)
	mapping, ok := normalized.(map[string]any)
	if !ok {
		return nil, errors.New("config root must be an object")
	}

	return mapping, nil
}

func normalize(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			result[key] = normalize(child)
		}
		return result
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			result[fmt.Sprint(key)] = normalize(child)
		}
		return result
	case []any:
		for index, child := range typed {
			typed[index] = normalize(child)
		}
		return typed
	default:
		return value
	}
}
