package analyser

import (
	"fmt"
	"strings"
)

type Node struct {
	Path  string
	Key   string
	Value any
}

func Walk(root map[string]any) []Node {
	nodes := make([]Node, 0)
	walkValue(root, "", "", &nodes)
	return nodes
}

func walkValue(value any, path string, key string, nodes *[]Node) {
	*nodes = append(*nodes, Node{Path: path, Key: key, Value: value})

	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			childPath := childKey
			if path != "" {
				childPath = path + "." + childKey
			}
			walkValue(child, childPath, childKey, nodes)
		}
	case []any:
		for index, child := range typed {
			childPath := fmt.Sprintf("[%d]", index)
			if path != "" {
				childPath = fmt.Sprintf("%s[%d]", path, index)
			}
			walkValue(child, childPath, key, nodes)
		}
	}
}

func containsAny(haystack string, needles ...string) bool {
	haystack = strings.ToLower(haystack)
	for _, needle := range needles {
		if strings.Contains(haystack, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func valueString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	default:
		return fmt.Sprint(typed), typed != nil
	}
}
