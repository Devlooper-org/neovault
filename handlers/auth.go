package handlers

import (
	"fmt"
	"log"

	"github.com/jigarvarma2k20/neovault/models"
	"github.com/jigarvarma2k20/neovault/repository"
	"github.com/jigarvarma2k20/neovault/utils"

	"github.com/gofiber/fiber/v3"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func ShowLogin(c fiber.Ctx) error {
	return c.Render("auth/login", fiber.Map{
		"Title": "Login - NeoVault",
	}, "layout")
}

func ShowRegister(c fiber.Ctx) error {
	return c.Render("auth/register", fiber.Map{
		"Title": "Register - NeoVault",
	}, "layout")
}

func Register(c fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	if username == "" || password == "" {
		return c.Render("auth/register", fiber.Map{
			"Error": "Username and password are required",
		}, "layout")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		log.Println("Error hashing password: ", err)
		return c.Status(500).SendString("Internal Server Error")
	}

	user := models.User{
		Username:     username,
		PasswordHash: string(hashedPassword),
	}

	if err := repository.CreateUser(&user); err != nil {
		return c.Render("auth/register", fiber.Map{
			"Error": "Username already exists",
		}, "layout")
	}

	// optional totp setup
	return c.Redirect().To(fmt.Sprintf("/totp/setup?user_id=%d", user.ID))
}

func Login(c fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	user, err := repository.GetUserByUsername(username)
	if err != nil {
		return c.Render("auth/login", fiber.Map{
			"Error": "Invalid credentials",
		}, "layout")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return c.Render("auth/login", fiber.Map{
			"Error": "Invalid credentials",
		}, "layout")
	}

	// totp setup check
	if user.TOTPSecret == "" {
		return c.Redirect().To(fmt.Sprintf("/totp/setup?user_id=%d", user.ID))
	}

	// verifcation before jwt
	tmpToken, err := utils.GenerateLoginToken(user.ID)
	if err != nil {
		return c.Status(500).SendString("Error generating token")
	}
	c.Cookie(&fiber.Cookie{
		Name:     "login_token",
		Value:    tmpToken,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
		MaxAge:   300, // 5 minutes to complete TOTP step
	})

	return c.Redirect().To("/totp/login")
}

// ShowTOTPLogin renders the TOTP code entry page during login
func ShowTOTPLogin(c fiber.Ctx) error {
	return c.Render("auth/totp_login", fiber.Map{
		"Title": "2FA Verification - NeoVault",
	}, "layout")
}

// VerifyTOTPLogin verifies the TOTP code and issues the full auth JWT
func VerifyTOTPLogin(c fiber.Ctx) error {
	loginToken := c.Cookies("login_token")
	if loginToken == "" {
		return c.Redirect().To("/login")
	}

	userID, err := utils.VerifyLoginToken(loginToken)
	if err != nil {
		c.ClearCookie("login_token")
		return c.Redirect().To("/login")
	}

	code := c.FormValue("code")
	user, err := repository.GetUserByID(userID)
	if err != nil {
		return c.Redirect().To("/login")
	}

	if !totp.Validate(code, user.TOTPSecret) {
		return c.Render("auth/totp_login", fiber.Map{
			"Title": "2FA Verification - NeoVault",
			"Error": "Invalid TOTP code. Please try again.",
		}, "layout")
	}

	// issue full token
	c.ClearCookie("login_token")

	tokenStr, err := utils.GenerateJWT(user.ID)
	if err != nil {
		return c.Status(500).SendString("Error generating token")
	}

	c.Cookie(&fiber.Cookie{
		Name:     "auth_token",
		Value:    tokenStr,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
	})

	return c.Redirect().To("/dashboard")
}

func Logout(c fiber.Ctx) error {
	c.ClearCookie("auth_token")
	c.ClearCookie("vault_token")
	return c.Redirect().To("/login")
}

// ChangePassword verifies the current account password and sets a new one.
func ChangePassword(c fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	currentPassword := c.FormValue("current_password")
	newPassword := c.FormValue("new_password")

	if currentPassword == "" || newPassword == "" {
		return c.Status(400).JSON(fiber.Map{"error": "All fields are required"})
	}
	if len(newPassword) < 8 {
		return c.Status(400).JSON(fiber.Map{"error": "New password must be at least 8 characters"})
	}

	user, err := repository.GetUserByID(userID)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Current password is incorrect"})
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Internal error"})
	}

	user.PasswordHash = string(newHash)
	if err := repository.UpdateUser(user); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update password"})
	}

	return c.JSON(fiber.Map{"ok": true})
}
