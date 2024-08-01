package defErr

import "errors"

func ConcatStr(err error, description string) error {
	return errors.Join(err, errors.New(description))
}

func StrConcat(description string, err error) error {
	return errors.Join(errors.New(description), err)
}

func PushErrorToErrChain(curr, toAdd error) error {
	return errors.Join(curr, StrConcat(`<-`, toAdd))
}
