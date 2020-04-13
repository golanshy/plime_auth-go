package user_domain

type User struct {
	Id              int64  `json:"id"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	Email           string `json:"email"`
	DateOfBirth     string `json:"date_of_birth"`
	Mobile          string `json:"mobile"`
	CountryCode     string `json:"country_code"`
	DateCreated     string `json:"date_created"`
	Status          string `json:"status"`
	Passcode        string `json:"passcode"`
	EmailValidated  bool   `json:"email_validated"`
	MobileValidated bool   `json:"mobile_validated"`
}