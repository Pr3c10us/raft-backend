package main

import (
	"errors"
	"github.com/go-playground/validator/v10"
	"net/http"
)

func (err *ValidationError) Error() string {
	return "validation failed"
}

func getErrorMessage(fieldError validator.FieldError) string {
	switch fieldError.Tag() {
	case "required":
		return fieldError.Field() + " is required"
	case "lte":
		return fieldError.Field() + " should be less than " + fieldError.Param()
	case "oneof":
		return fieldError.Field() + " should be one off " + fieldError.Param()
	case "gte":
		return fieldError.Field() + " should be greater than " + fieldError.Param()
	case "email":
		return "Invalid email format"
	case "uuid":
		return "Invalid uuid format"
	case "timeformat":
		return "Invalid time format hh:mm"
	case "questionpos":
		return "question position must be greater than previous by one"
	case "timezone":
		return "Invalid time zone"
	case "min":
		return fieldError.Field() + " should be at least " + fieldError.Param() + " item"
	case "max":
		return fieldError.Field() + " should be at most " + fieldError.Param() + " item"
	case "e164":
		return fieldError.Field() + " should be in valid E.164 format"
	default:
		return "Unknown error on field " + fieldError.Field()
	}
}

func ValidateRequest(err error) error {
	if err == nil {
		return nil
	}
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		errorMessages := make([]ErrorMessage, len(validationErrors))
		for i, fieldError := range validationErrors {
			errorMessages[i] = ErrorMessage{fieldError.Field(), getErrorMessage(fieldError)}
		}
		return &ValidationError{
			StatusCode:   http.StatusNotAcceptable,
			Message:      "validation failed",
			ErrorMessage: errorMessages,
		}
	}
	return err
}
