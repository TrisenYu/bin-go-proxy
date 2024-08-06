package defErr

import "errors"

// err concatenates to err(str)
func ConcatStr(err error, description string) error {
	return errors.Join(err, errors.New(description))
}

// err(str) concatenates to err.
func StrConcat(description string, err error) error {
	return errors.Join(errors.New(description), err)
}

// invoke this function when the continuous execution can be endured and form error as a stack-chain.
func PushErrorToErrChain(curr, toAdd error) error {
	return errors.Join(curr, StrConcat(`<-`, toAdd))
}
