package constants

const (
	CodeUsernameIsAlreadyTaken = "USERNAME_IS_ALREADY_TAKEN"
	CodeUsernameTooShort       = "USERNAME_TOO_SHORT"
	CodeUsernameTooLong        = "USERNAME_TOO_LONG"
	CodeInvalidDisplayUsername = "INVALID_DISPLAY_USERNAME"
)

const (
	MsgUsernameIsAlreadyTaken = "Username is already taken. Please try another."
	MsgUsernameTooShort       = "Username is too short"
	MsgUsernameTooLong        = "Username is too long"
	MsgInvalidDisplayUsername = "Display username is invalid"
)

func init() {
	apiMessages[CodeUsernameIsAlreadyTaken] = MsgUsernameIsAlreadyTaken
	apiMessages[CodeUsernameTooShort] = MsgUsernameTooShort
	apiMessages[CodeUsernameTooLong] = MsgUsernameTooLong
	apiMessages[CodeInvalidDisplayUsername] = MsgInvalidDisplayUsername
}
