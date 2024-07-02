package defErr

import "errors"

func Concat(err error, description string) error {
	return errors.Join(err, errors.New(description))
}

func DescribeThenConcat(description string, err error) error {
	return errors.Join(errors.New(description), err)
}

func PushErrorToErrChain(curr, toAdd error) error {
	return errors.Join(curr, DescribeThenConcat(`<-`, toAdd))
}
