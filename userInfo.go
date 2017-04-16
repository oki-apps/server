package server

import (
	"context"
	"errors"
)

type key int

const userInfoKey key = 0

func newContextWithUserInfo(ctx context.Context, u userInfo) context.Context {
	return context.WithValue(ctx, userInfoKey, u)
}

//UserInfo contains basic information for an authenticated user
type UserInfo interface {
	ID() string
	DisplayName() string
	Email() string
}

type userInfo struct {
	subject string
	name    string
	email   string
}

func (u userInfo) ID() string {
	return u.subject
}
func (u userInfo) DisplayName() string {
	return u.name
}
func (u userInfo) Email() string {
	return u.email
}

//GetUserInfo returns the current ID of the logged in user, if any
func GetUserInfo(ctx context.Context) (UserInfo, error) {
	userInfo, ok := ctx.Value(userInfoKey).(userInfo)
	if !ok {
		return nil, errors.New("Invalid user ID")
	}

	return userInfo, nil
}
