package validator

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

const (
	lenErrMsg = "length must be equal to %s"
	maxErrMsg = "must be less than or equal to %s"
	minErrMsg = "must be greater than or equal to %s"
	inErrMsg  = "must be in [%s]"
)

const (
	validateTag    = "validate"
	lenValidator   = "len"
	maxValidator   = "max"
	minValidator   = "min"
	inValidator    = "in"
	validValidator = "valid" // nested validation
)

var (
	ErrNotStruct                   = errors.New("wrong argument given, should be a struct")
	ErrInvalidValidatorSyntax      = errors.New("invalid validator syntax")
	ErrValidateForUnexportedFields = errors.New("validation for unexported field is not allowed")
	ErrValidateForUnsupportedTypes = errors.New("validation for unsupported type is not allowed")
	ErrUnsupportedValidator        = errors.New("validator for this type is unsupported")
)

type ValidationError struct {
	Err   error
	field string
	tag   string
	val   any
}

func (v ValidationError) Field() string {
	return v.field
}

func (v ValidationError) Tag() string {
	return v.tag
}

func (v ValidationError) Value() any {
	return v.val
}

func (v ValidationError) Error() string {
	return v.Err.Error()
}

type ValidationErrors []ValidationError

func (v ValidationErrors) Error() string {
	errs := make([]string, len(v))
	for i := range v {
		errs[i] = v[i].Error()
	}
	return strings.Join(errs, "\n")
}

func Validate(v any) error {
	val := reflect.ValueOf(v)

	if val.Kind() == reflect.Ptr && !val.IsNil() {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return ErrNotStruct
	}

	return validateStruct(val)
}

func validateStruct(v reflect.Value) error {
	fields := reflect.VisibleFields(v.Type())
	if len(fields) == 0 {
		return nil
	}

	errs := make(ValidationErrors, 0)
	for _, f := range fields {
		tagVal, ok := f.Tag.Lookup(validateTag)
		if !ok {
			continue
		}

		fieldVal := v.FieldByIndex(f.Index)

		if !f.IsExported() {
			errs = append(errs,
				ValidationError{
					Err:   ErrValidateForUnexportedFields,
					field: f.Name,
					tag:   tagVal,
				},
			)
			continue
		}

		var err *ValidationError
		switch f.Type.Kind() {
		case reflect.Struct:
			if tagVal == validValidator {
				nestedStructErrs := validateStruct(fieldVal)
				if nestedStructErrs != nil {
					errs = append(errs,
						validateStruct(fieldVal).(ValidationErrors)...,
					)
				}
			}
			continue
		case reflect.Int:
			err = validateInt64(fieldVal.Int(), tagVal)
		case reflect.String:
			err = validateString(fieldVal.String(), tagVal)
		default:
			err = &ValidationError{Err: ErrValidateForUnsupportedTypes}
		}

		if err != nil {
			err.field = f.Name
			err.tag = tagVal
			err.val = fieldVal.Interface()
			errs = append(errs, *err)
		}
	}

	if len(errs) != 0 {
		return errs
	}

	return nil
}

func validateString(s string, tagVal string) *ValidationError {
	ts := strings.Split(tagVal, ":")
	if len(ts) < 2 || ts[1] == "" {
		return &ValidationError{Err: ErrInvalidValidatorSyntax}
	}
	validator := ts[0]
	validatorVal := ts[1]

	if validator == inValidator {
		in := strings.Split(validatorVal, ",")
		if len(in) <= 0 {
			return &ValidationError{Err: ErrInvalidValidatorSyntax}
		}
		for i := range in {
			if in[i] == s {
				return nil
			}
		}
		return &ValidationError{Err: errors.New(fmt.Sprintf(inErrMsg, validatorVal))}
	}

	l, err := strconv.Atoi(validatorVal)
	if err != nil {
		return &ValidationError{Err: ErrInvalidValidatorSyntax}
	}

	switch validator {
	case lenValidator:
		if l < 0 {
			return &ValidationError{Err: ErrInvalidValidatorSyntax}
		}
		if len(s) != l {
			return &ValidationError{Err: errors.New(fmt.Sprintf(lenErrMsg, validatorVal))}
		}
	case maxValidator:
		if len(s) > l {
			return &ValidationError{Err: errors.New(fmt.Sprintf(maxErrMsg, validatorVal))}
		}
	case minValidator:
		if len(s) < l {
			return &ValidationError{Err: errors.New(fmt.Sprintf(minErrMsg, validatorVal))}
		}
	default:
		return &ValidationError{Err: ErrUnsupportedValidator}
	}

	return nil
}
func validateInt64(n int64, tagVal string) *ValidationError {
	ts := strings.Split(tagVal, ":")
	if len(ts) < 2 || ts[1] == "" {
		return &ValidationError{Err: ErrInvalidValidatorSyntax}
	}
	validator := ts[0]
	validatorVal := ts[1]

	if validator == inValidator {
		in := strings.Split(validatorVal, ",")
		if len(in) <= 0 {
			return &ValidationError{Err: ErrInvalidValidatorSyntax}
		}
		for i := range in {
			l, err := strconv.Atoi(in[i])
			if err != nil {
				return &ValidationError{Err: ErrInvalidValidatorSyntax}
			}
			if int64(l) == n {
				return nil
			}
		}
		return &ValidationError{Err: errors.New(fmt.Sprintf(inErrMsg, validatorVal))}
	}

	l, err := strconv.Atoi(validatorVal)
	if err != nil {
		return &ValidationError{Err: ErrInvalidValidatorSyntax}
	}

	switch validator {
	case maxValidator:
		if n > int64(l) {
			return &ValidationError{Err: errors.New(fmt.Sprintf(maxErrMsg, validatorVal))}
		}
	case minValidator:
		if n < int64(l) {
			return &ValidationError{Err: errors.New(fmt.Sprintf(minErrMsg, validatorVal))}
		}
	default:
		return &ValidationError{Err: ErrUnsupportedValidator}
	}

	return nil
}
