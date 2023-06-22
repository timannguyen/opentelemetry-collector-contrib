// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package helper // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator/helper"

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/entry"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/errors"
)

// NewParserConfig creates a new parser config with default values
func NewParserConfig(operatorID, operatorType string) ParserConfig {
	return ParserConfig{
		TransformerConfig: NewTransformerConfig(operatorID, operatorType),
		ParseFrom:         entry.NewBodyField(),
		ParseTo:           entry.RootableField{Field: entry.NewAttributeField()},
	}
}

// ParserConfig provides the basic implementation of a parser config.
type ParserConfig struct {
	TransformerConfig `mapstructure:",squash"`
	ParseFrom         entry.Field         `mapstructure:"parse_from"`
	ParseTo           entry.RootableField `mapstructure:"parse_to"`
	BodyField         *entry.Field        `mapstructure:"body"`
	TimeParser        *TimeParser         `mapstructure:"timestamp,omitempty"`
	SeverityConfig    *SeverityConfig     `mapstructure:"severity,omitempty"`
	TraceParser       *TraceParser        `mapstructure:"trace,omitempty"`
	ScopeNameParser   *ScopeNameParser    `mapstructure:"scope_name,omitempty"`
}

// Build will build a parser operator.
func (c ParserConfig) Build(logger *zap.SugaredLogger) (ParserOperator, error) {
	transformerOperator, err := c.TransformerConfig.Build(logger)
	if err != nil {
		return ParserOperator{}, err
	}

	if c.BodyField != nil && c.ParseTo.String() == entry.NewBodyField().String() {
		return ParserOperator{}, fmt.Errorf("`parse_to: body` not allowed when `body` is configured")
	}

	parserOperator := ParserOperator{
		TransformerOperator: transformerOperator,
		ParseFrom:           c.ParseFrom,
		ParseTo:             c.ParseTo.Field,
		BodyField:           c.BodyField,
	}

	if c.TimeParser != nil {
		if err := c.TimeParser.Validate(); err != nil {
			return ParserOperator{}, err
		}
		parserOperator.TimeParser = c.TimeParser
	}

	if c.SeverityConfig != nil {
		severityParser, err := c.SeverityConfig.Build(logger)
		if err != nil {
			return ParserOperator{}, err
		}
		parserOperator.SeverityParser = &severityParser
	}

	if c.TraceParser != nil {
		if err := c.TraceParser.Validate(); err != nil {
			return ParserOperator{}, err
		}
		parserOperator.TraceParser = c.TraceParser
	}

	if c.ScopeNameParser != nil {
		parserOperator.ScopeNameParser = c.ScopeNameParser
	}

	return parserOperator, nil
}

// ParserOperator provides a basic implementation of a parser operator.
type ParserOperator struct {
	TransformerOperator
	ParseFrom       entry.Field
	ParseTo         entry.Field
	BodyField       *entry.Field
	TimeParser      *TimeParser
	SeverityParser  *SeverityParser
	TraceParser     *TraceParser
	ScopeNameParser *ScopeNameParser
}

// ProcessWith will run ParseWith on the entrxy, then forward the entry on to the next operators.
func (p *ParserOperator) ProcessWith(ctx context.Context, entry *entry.Entry, parse ParseFunction) error {
	return p.ProcessWithCallback(ctx, entry, parse, nil, p.WriteWithSingleEvent)
}

func (p *ParserOperator) ProcessWithCallback(ctx context.Context, entry *entry.Entry, parse ParseFunction, cb func(*entry.Entry) error, writeWith WriteFunction) error {
	// Short circuit if the "if" condition does not match
	skip, err := p.Skip(ctx, entry)
	if err != nil {
		return p.HandleEntryError(ctx, entry, err)
	}
	if skip {
		p.Write(ctx, entry)
		return nil
	}

	return writeWith(ctx, entry, cb, parse)
}

func (p *ParserOperator) WriteWithSingleEvent(ctx context.Context, entry *entry.Entry, cb func(*entry.Entry) error, parse ParseFunction) error {
	if err := p.ParseWith(ctx, entry, parse); err != nil {
		return err
	}
	if cb != nil {
		err := cb(entry)
		if err != nil {
			return err
		}
	}

	p.Write(ctx, entry)
	return nil
}

func (p *ParserOperator) WriteWithMultiEvents(ctx context.Context, entry *entry.Entry, cb func(*entry.Entry) error, parse ParseFunction) error {
	entries, err := p.ParseWithMulti(ctx, entry, parse)
	if err != nil {
		return err
	}
	entriesLen := len(entries)
	for i := 0; i < entriesLen; i++ {
		if cb != nil {
			err := cb(entries[i])
			if err != nil {
				return err
			}
		}
		p.Write(ctx, entries[i])
	}
	return nil
}

// ParseWith will process an entry's field with a parser function.
func (p *ParserOperator) ParseWith(ctx context.Context, entry *entry.Entry, parse ParseFunction) error {
	value, ok := entry.Get(p.ParseFrom)
	if !ok {
		err := errors.NewError(
			"Entry is missing the expected parse_from field.",
			"Ensure that all incoming entries contain the parse_from field.",
			"parse_from", p.ParseFrom.String(),
		)
		return p.HandleEntryError(ctx, entry, err)
	}

	newValue, err := parse(value)
	if err != nil {
		return p.HandleEntryError(ctx, entry, err)
	}

	if err := entry.Set(p.ParseTo, newValue); err != nil {
		return p.HandleEntryError(ctx, entry, errors.Wrap(err, "set parse_to"))
	}

	if p.BodyField != nil {
		if body, ok := p.BodyField.Get(entry); ok {
			entry.Body = body
		}
	}

	var timeParseErr error
	if p.TimeParser != nil {
		timeParseErr = p.TimeParser.Parse(entry)
	}

	var severityParseErr error
	if p.SeverityParser != nil {
		severityParseErr = p.SeverityParser.Parse(entry)
	}

	var traceParseErr error
	if p.TraceParser != nil {
		traceParseErr = p.TraceParser.Parse(entry)
	}

	var scopeNameParserErr error
	if p.ScopeNameParser != nil {
		scopeNameParserErr = p.ScopeNameParser.Parse(entry)
	}

	// Handle parsing errors after attempting to parse all
	if timeParseErr != nil {
		return p.HandleEntryError(ctx, entry, errors.Wrap(timeParseErr, "time parser"))
	}
	if severityParseErr != nil {
		return p.HandleEntryError(ctx, entry, errors.Wrap(severityParseErr, "severity parser"))
	}
	if traceParseErr != nil {
		return p.HandleEntryError(ctx, entry, errors.Wrap(traceParseErr, "trace parser"))
	}
	if scopeNameParserErr != nil {
		return p.HandleEntryError(ctx, entry, errors.Wrap(scopeNameParserErr, "scope_name parser"))
	}
	return nil
}

// ParseWithMulti will process an entry's field with a parser function and expect multiple entries are parsed from a single entry
func (p *ParserOperator) ParseWithMulti(ctx context.Context, e *entry.Entry, parse ParseFunction) ([]*entry.Entry, error) {
	value, ok := e.Get(p.ParseFrom)
	if !ok {
		err := errors.NewError(
			"Entry is missing the expected parse_from field.",
			"Ensure that all incoming entries contain the parse_from field.",
			"parse_from", p.ParseFrom.String(),
		)
		return nil, p.HandleEntryError(ctx, e, err)
	}

	newValues, err := parse(value)
	if err != nil {
		return nil, p.HandleEntryError(ctx, e, err)
	}

	newValuesLen := len(newValues.([]map[string]interface{}))
	entries := make([]*entry.Entry, newValuesLen)
	var newEntry *entry.Entry
	if newValuesLen == 1 {
		if err = p.postParseFunction(ctx, e, newValues.([]map[string]interface{})[0]); err != nil {
			return nil, err
		}
		entries[0] = e
	} else {
		for i := 0; i < newValuesLen; i++ {
			newEntry = entry.New()
			newEntry.ObservedTimestamp = e.ObservedTimestamp
			// intentionally not passing on body as it could max log size
			if err = p.postParseFunction(ctx, newEntry, newValues.([]map[string]interface{})[i]); err != nil {
				return nil, err
			}
			entries[i] = newEntry
		}
	}
	return entries, nil
}

func (p *ParserOperator) postParseFunction(ctx context.Context, e *entry.Entry, newValues interface{}) error {
	if err := e.Set(p.ParseTo, newValues); err != nil {
		return p.HandleEntryError(ctx, e, errors.Wrap(err, "set parse_to"))
	}

	if p.BodyField != nil {
		if body, ok := p.BodyField.Get(e); ok {
			e.Body = body
		}
	}

	var timeParseErr error
	if p.TimeParser != nil {
		timeParseErr = p.TimeParser.Parse(e)
	}

	var severityParseErr error
	if p.SeverityParser != nil {
		severityParseErr = p.SeverityParser.Parse(e)
	}

	var traceParseErr error
	if p.TraceParser != nil {
		traceParseErr = p.TraceParser.Parse(e)
	}

	var scopeNameParserErr error
	if p.ScopeNameParser != nil {
		scopeNameParserErr = p.ScopeNameParser.Parse(e)
	}

	// Handle parsing errors after attempting to parse all
	if timeParseErr != nil {
		return p.HandleEntryError(ctx, e, errors.Wrap(timeParseErr, "time parser"))
	}
	if severityParseErr != nil {
		return p.HandleEntryError(ctx, e, errors.Wrap(severityParseErr, "severity parser"))
	}
	if traceParseErr != nil {
		return p.HandleEntryError(ctx, e, errors.Wrap(traceParseErr, "trace parser"))
	}
	if scopeNameParserErr != nil {
		return p.HandleEntryError(ctx, e, errors.Wrap(scopeNameParserErr, "scope_name parser"))
	}
	return nil
}

// ParseFunction is function that parses a raw value.
type ParseFunction = func(interface{}) (interface{}, error)
type WriteFunction = func(ctx context.Context, entry *entry.Entry, cb func(*entry.Entry) error, parse ParseFunction) error
