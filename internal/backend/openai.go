package backend

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Message is one chat message in the supported V1 non-streaming shape.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is the reconstructed supported-field-only backend request.
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature *float64  `json:"temperature,omitempty"`
	MaxTokens   *int      `json:"max_tokens,omitempty"`
}

// Usage is validated backend token accounting.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatResult is the parsed completion plus exact response bytes for hashing.
type ChatResult struct {
	ID      string
	Model   string
	Content string
	Usage   Usage
	RawJSON []byte
}

type wireChatRequest struct {
	Model       string          `json:"model"`
	Messages    []wireMessage   `json:"messages"`
	Temperature *float64        `json:"temperature"`
	MaxTokens   *int            `json:"max_tokens"`
	Stream      *bool           `json:"stream"`
	Tools       json.RawMessage `json:"tools"`
	Functions   json.RawMessage `json:"functions"`
	Modalities  json.RawMessage `json:"modalities"`
	ToolChoice  json.RawMessage `json:"tool_choice"`
}

type wireMessage struct {
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	Name      json.RawMessage `json:"name"`
	ToolCalls json.RawMessage `json:"tool_calls"`
}

// ParseChatRequest strictly decodes a supported non-streaming chat request.
// Unknown fields, streaming, tools, modalities, and non-text content are rejected.
func ParseChatRequest(raw []byte) (ChatRequest, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return ChatRequest{}, ErrInvalidRequest
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var wire wireChatRequest
	if err := dec.Decode(&wire); err != nil {
		return ChatRequest{}, ErrInvalidRequest
	}
	if dec.More() {
		return ChatRequest{}, ErrInvalidRequest
	}
	return chatRequestFromWire(wire)
}

func chatRequestFromWire(wire wireChatRequest) (ChatRequest, error) {
	if wire.Stream != nil && *wire.Stream {
		return ChatRequest{}, ErrInvalidRequest
	}
	if len(wire.Tools) > 0 || len(wire.Functions) > 0 || len(wire.Modalities) > 0 || len(wire.ToolChoice) > 0 {
		return ChatRequest{}, ErrInvalidRequest
	}
	if strings.TrimSpace(wire.Model) == "" || len(wire.Messages) == 0 || len(wire.Messages) > 128 {
		return ChatRequest{}, ErrInvalidRequest
	}
	messages := make([]Message, 0, len(wire.Messages))
	for _, msg := range wire.Messages {
		if msg.Role != "system" && msg.Role != "user" && msg.Role != "assistant" {
			return ChatRequest{}, ErrInvalidRequest
		}
		if len(msg.ToolCalls) > 0 || len(msg.Name) > 0 {
			return ChatRequest{}, ErrInvalidRequest
		}
		var content string
		if err := json.Unmarshal(msg.Content, &content); err != nil {
			return ChatRequest{}, ErrInvalidRequest
		}
		if content == "" && msg.Role != "assistant" {
			return ChatRequest{}, ErrInvalidRequest
		}
		messages = append(messages, Message{Role: msg.Role, Content: content})
	}
	if wire.Temperature != nil && (*wire.Temperature < 0 || *wire.Temperature > 2) {
		return ChatRequest{}, ErrInvalidRequest
	}
	if wire.MaxTokens != nil && *wire.MaxTokens <= 0 {
		return ChatRequest{}, ErrInvalidRequest
	}
	return ChatRequest{
		Model:       wire.Model,
		Messages:    messages,
		Temperature: wire.Temperature,
		MaxTokens:   wire.MaxTokens,
	}, nil
}

func validateChatRequest(req ChatRequest) error {
	if strings.TrimSpace(req.Model) == "" || len(req.Messages) == 0 || len(req.Messages) > 128 {
		return ErrInvalidRequest
	}
	for _, msg := range req.Messages {
		if msg.Role != "system" && msg.Role != "user" && msg.Role != "assistant" {
			return ErrInvalidRequest
		}
		if msg.Content == "" && msg.Role != "assistant" {
			return ErrInvalidRequest
		}
	}
	if req.Temperature != nil && (*req.Temperature < 0 || *req.Temperature > 2) {
		return ErrInvalidRequest
	}
	if req.MaxTokens != nil && *req.MaxTokens <= 0 {
		return ErrInvalidRequest
	}
	return nil
}

func encodeChatRequest(req ChatRequest) ([]byte, error) {
	if err := validateChatRequest(req); err != nil {
		return nil, err
	}
	payload := struct {
		Model       string    `json:"model"`
		Messages    []Message `json:"messages"`
		Temperature *float64  `json:"temperature,omitempty"`
		MaxTokens   *int      `json:"max_tokens,omitempty"`
	}{
		Model:       req.Model,
		Messages:    req.Messages,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	return raw, nil
}

type wireChatResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *Usage `json:"usage"`
}

func parseChatResponse(raw []byte) (ChatResult, error) {
	var wire wireChatResponse
	if err := json.Unmarshal(raw, &wire); err != nil {
		return ChatResult{}, ErrInvalidResponse
	}
	if wire.Object != "" && wire.Object != "chat.completion" {
		return ChatResult{}, ErrInvalidResponse
	}
	if len(wire.Choices) == 0 {
		return ChatResult{}, ErrInvalidResponse
	}
	choice := wire.Choices[0]
	if choice.Message.Role != "" && choice.Message.Role != "assistant" {
		return ChatResult{}, ErrInvalidResponse
	}
	if wire.Usage == nil {
		return ChatResult{}, ErrUsageInvalid
	}
	if err := validateUsage(*wire.Usage); err != nil {
		return ChatResult{}, err
	}
	copied := append([]byte(nil), raw...)
	return ChatResult{
		ID:      wire.ID,
		Model:   wire.Model,
		Content: choice.Message.Content,
		Usage:   *wire.Usage,
		RawJSON: copied,
	}, nil
}

func validateUsage(usage Usage) error {
	if usage.PromptTokens < 0 || usage.CompletionTokens < 0 || usage.TotalTokens < 0 {
		return ErrUsageInvalid
	}
	sum := usage.PromptTokens + usage.CompletionTokens
	// Require exact sum so backends cannot under-report total relative to parts.
	if usage.TotalTokens != sum {
		return ErrUsageInvalid
	}
	return nil
}
