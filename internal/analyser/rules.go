package analyser

import (
	"fmt"
	"strings"
)

type DebugLoggingRule struct{}

func (DebugLoggingRule) ID() string { return "debug_logging" }

func (rule DebugLoggingRule) Check(doc Document) []Issue {
	var issues []Issue
	for _, node := range Walk(doc.Root) {
		raw, ok := valueString(node.Value)
		if !ok {
			continue
		}

		value := strings.ToLower(strings.TrimSpace(raw))
		if value != "debug" && value != "trace" {
			continue
		}

		if node.Key == "level" || containsAny(node.Path, "log", "logging") {
			issues = append(issues, Issue{
				Severity:       SeverityLow,
				RuleID:         rule.ID(),
				Message:        "логирование в debug/trace-режиме может раскрывать лишние детали работы приложения",
				Recommendation: "Поменяйте уровень логирования на info или выше для production-окружения.",
				Path:           node.Path,
			})
		}
	}
	return issues
}

type PlaintextSecretRule struct{}

func (PlaintextSecretRule) ID() string { return "plaintext_secret" }

func (rule PlaintextSecretRule) Check(doc Document) []Issue {
	var issues []Issue
	for _, node := range Walk(doc.Root) {
		raw, ok := node.Value.(string)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}

		key := strings.ToLower(node.Key)
		if !isSensitiveKey(key) || isEnvReference(raw) {
			continue
		}

		issues = append(issues, Issue{
			Severity:       SeverityHigh,
			RuleID:         rule.ID(),
			Message:        fmt.Sprintf("секретное значение в ключе %q хранится в открытом виде", node.Path),
			Recommendation: "Храните секреты в .env или secret storage и передавайте в конфиг только ссылку на переменную окружения.",
			Path:           node.Path,
		})
	}
	return issues
}

func isSensitiveKey(key string) bool {
	if key == "" {
		return false
	}

	key = strings.ReplaceAll(key, "-", "_")
	candidates := []string{"password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "private_key", "access_key"}
	for _, candidate := range candidates {
		if key == candidate || strings.Contains(key, candidate) {
			return true
		}
	}
	return false
}

func isEnvReference(value string) bool {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	return strings.HasPrefix(value, "$") ||
		(strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}")) ||
		strings.HasPrefix(lower, "env:") ||
		strings.HasPrefix(lower, "env.")
}

type WildcardBindRule struct{}

func (WildcardBindRule) ID() string { return "wildcard_bind" }

func (rule WildcardBindRule) Check(doc Document) []Issue {
	if hasNetworkRestrictions(doc.Root) {
		return nil
	}

	var issues []Issue
	for _, node := range Walk(doc.Root) {
		raw, ok := valueString(node.Value)
		if !ok {
			continue
		}

		if isWildcardAddress(raw) {
			issues = append(issues, Issue{
				Severity:       SeverityMedium,
				RuleID:         rule.ID(),
				Message:        "приложение слушает на 0.0.0.0 или :: без явных ограничений доступа",
				Recommendation: "Ограничьте bind-адрес, добавьте allowlist/firewall-настройки или используйте reverse proxy с контролем доступа.",
				Path:           node.Path,
			})
		}
	}
	return issues
}

func isWildcardAddress(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "0.0.0.0" ||
		value == "::" ||
		value == "[::]" ||
		strings.HasPrefix(value, "0.0.0.0:") ||
		strings.HasPrefix(value, "[::]:") ||
		strings.Contains(value, "://0.0.0.0:")
}

func hasNetworkRestrictions(root map[string]any) bool {
	for _, node := range Walk(root) {
		if !containsAny(node.Path, "allowlist", "whitelist", "allowed", "firewall", "trusted_proxy", "trusted-proxy", "cidr") {
			continue
		}

		switch value := node.Value.(type) {
		case string:
			if strings.TrimSpace(value) != "" && strings.TrimSpace(value) != "*" {
				return true
			}
		case []any:
			return len(value) > 0
		case map[string]any:
			return len(value) > 0
		case bool:
			return value
		}
	}
	return false
}

type DisabledTLSRule struct{}

func (DisabledTLSRule) ID() string { return "disabled_tls" }

func (rule DisabledTLSRule) Check(doc Document) []Issue {
	var issues []Issue
	for _, node := range Walk(doc.Root) {
		keyPath := strings.ToLower(node.Path)
		value, isBool := node.Value.(bool)
		if !isBool {
			continue
		}

		disabledPositiveFlag := containsAny(keyPath, "insecure", "skip_verify", "skip-verify", "disable_tls", "disable-tls")
		verifyFlag := containsAny(keyPath, "verify", "tls", "ssl") && !disabledPositiveFlag

		if (disabledPositiveFlag && value) || (verifyFlag && !value) {
			issues = append(issues, Issue{
				Severity:       SeverityHigh,
				RuleID:         rule.ID(),
				Message:        "TLS-проверка отключена или используется небезопасный TLS-режим",
				Recommendation: "Включите проверку TLS-сертификатов и не используйте insecure/skip verify в production.",
				Path:           node.Path,
			})
		}
	}
	return issues
}

type WeakAlgorithmRule struct{}

func (WeakAlgorithmRule) ID() string { return "weak_algorithm" }

func (rule WeakAlgorithmRule) Check(doc Document) []Issue {
	weak := map[string]struct{}{
		"md5": {}, "sha1": {}, "des": {}, "3des": {}, "rc4": {}, "none": {}, "rsa1024": {},
	}

	var issues []Issue
	for _, node := range Walk(doc.Root) {
		raw, ok := valueString(node.Value)
		if !ok {
			continue
		}

		normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", ""))
		if _, found := weak[normalized]; !found {
			continue
		}

		if !containsAny(node.Path, "algorithm", "digest", "hash", "cipher", "crypto", "signature", "encryption") {
			continue
		}

		issues = append(issues, Issue{
			Severity:       SeverityHigh,
			RuleID:         rule.ID(),
			Message:        fmt.Sprintf("используется устаревший или небезопасный алгоритм: %s", raw),
			Recommendation: "Замените алгоритм на актуальный безопасный вариант, например SHA-256/Argon2id/AES-GCM в зависимости от назначения.",
			Path:           node.Path,
		})
	}
	return issues
}

type FilePermissionRule struct{}

func (FilePermissionRule) ID() string { return "file_permissions" }

func (rule FilePermissionRule) Check(doc Document) []Issue {
	if !doc.Metadata.HasMode {
		return nil
	}

	mode := doc.Metadata.FileMode & 0o777
	if mode&0o002 != 0 {
		return []Issue{{
			Severity:       SeverityHigh,
			RuleID:         rule.ID(),
			Message:        fmt.Sprintf("файл конфигурации доступен на запись всем пользователям: %04o", mode),
			Recommendation: "Ограничьте права доступа к файлу конфигурации, например до 0600 или 0640.",
			Path:           "$file.mode",
		}}
	}

	if mode&0o077 != 0 {
		return []Issue{{
			Severity:       SeverityMedium,
			RuleID:         rule.ID(),
			Message:        fmt.Sprintf("у файла конфигурации слишком широкие права доступа: %04o", mode),
			Recommendation: "Ограничьте чтение конфигурации владельцем или доверенной группой, например 0600 или 0640.",
			Path:           "$file.mode",
		}}
	}

	return nil
}
