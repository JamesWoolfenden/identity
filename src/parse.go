package identity

import (
	"encoding/json"
	"reflect"
)

func Parse(raw string) Policy {
	var aJSON map[string]interface{}
	err := json.Unmarshal([]byte(raw), &aJSON)
	if err != nil {
		panic(err)
	}
	var myPolicy Policy

	myPolicy.Version = aJSON["Version"].(string)

	for _, statement := range aJSON["Statement"].([]interface{}) {
		myStatement := Statement{}
		myStatement.Effect = statement.(map[string]interface{})["Effect"].(string)
		rawResource := statement.(map[string]interface{})["Resource"]

		if isSlice(rawResource) {
			for _, v := range rawResource.([]interface{}) {
				myStatement.Resource = append(myStatement.Resource, v.(string))
			}
		} else {
			myStatement.Resource = append(myStatement.Resource, rawResource.(string))
		}

		if isSlice(statement.(map[string]interface{})["Action"]) {
			for _, v := range statement.(map[string]interface{})["Action"].([]interface{}) {
				myStatement.Action = append(myStatement.Action, v.(string))
			}
		} else {
			myStatement.Action = append(myStatement.Action, statement.(map[string]interface{})["Action"].(string))
		}

		myPolicy.Statements = append(myPolicy.Statements, myStatement)
	}

	return myPolicy
}

func isArray(arr interface{}) bool {
	// Get the type of the variable using reflection
	t := reflect.TypeOf(arr)

	// Check if the type is an array
	return t.Kind() == reflect.Array
}

func isSlice(arr interface{}) bool {
	// Get the type of the variable using reflection
	t := reflect.TypeOf(arr)

	// Check if the type is an array
	return t.Kind() == reflect.Slice
}