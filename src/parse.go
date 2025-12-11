package Identity

import (
	"encoding/json"
	"fmt"
	"reflect"
)

type EmptyParseError struct{}

const (
	UserType       = "user"
	GroupType      = "group"
	RoleType       = "role"
	VersionField   = "Version"
	StatementField = "Statement"
	SidField       = "Sid"
	EffectField    = "Effect"
	ResourceField  = "Resource"
	ActionField    = "Action"
)

func NewPolicy() Policy {
	return Policy{
		Version:    "",
		Statements: make([]Statement, 0),
	}
}

func (m *EmptyParseError) Error() string {
	return "cannot parse such empty"
}

func Parse(raw string) (Policy, error) {
	if raw == "" {
		return NewPolicy(), &EmptyParseError{}
	}

	var aJSON map[string]interface{}

	err := json.Unmarshal([]byte(raw), &aJSON)

	if err != nil {
		return NewPolicy(), err
	}

	var myPolicy Policy

	if version, ok := aJSON[VersionField].(string); ok {
		myPolicy.Version = version
	} else {
		return NewPolicy(), fmt.Errorf("invalid Version format")
	}

	if statements, ok := aJSON[StatementField].([]interface{}); ok {
		for _, statement := range statements {
			myPolicy, err = parseIamStatement(statement, myPolicy)
		}
	} else {
		myPolicy, err = parseIamStatement(aJSON[StatementField], myPolicy)
	}

	return myPolicy, err
}

func parseIamStatement(statement interface{}, myPolicy Policy) (Policy, error) {
	myStatement := Statement{}

	if sid, ok := statement.(map[string]interface{})[SidField].(string); ok {
		myStatement.Sid = sid
	}

	if effect, ok := statement.(map[string]interface{})[EffectField].(string); ok {
		myStatement.Effect = effect
	} else {
		return NewPolicy(), fmt.Errorf("invalid Effect format")
	}

	rawResource := statement.(map[string]interface{})[ResourceField]

	if isSlice(rawResource) {
		for _, v := range rawResource.([]interface{}) {
			myStatement.Resource = append(myStatement.Resource, v.(string))
		}
	} else {
		myStatement.Resource = append(myStatement.Resource, rawResource.(string))
	}

	if isSlice(statement.(map[string]interface{})[ActionField]) {
		for _, v := range statement.(map[string]interface{})[ActionField].([]interface{}) {
			myStatement.Action = append(myStatement.Action, v.(string))
		}
	} else {
		myStatement.Action = append(myStatement.Action, statement.(map[string]interface{})[ActionField].(string))
	}

	myPolicy.Statements = append(myPolicy.Statements, myStatement)

	return myPolicy, nil
}

func isSlice(arr interface{}) bool {
	// Get the type of the variable using reflection
	t := reflect.TypeOf(arr)

	// Check if the type is an array
	return t.Kind() == reflect.Slice
}
