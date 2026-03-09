package handlers

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"image/png"
	"log"
	"strconv"

	"github.com/jigarvarma2k20/neovault/repository"
	"github.com/jigarvarma2k20/neovault/utils"

	"github.com/gofiber/fiber/v3"
	"github.com/pquerna/otp/totp"
)

// ShowTOTPSetup renders the TOTP setup page with QR code
func ShowTOTPSetup(c fiber.Ctx) error {
	userIDStr := c.Query("user_id")
	if userIDStr == "" {
		return c.Redirect().To("/login")
	}

	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		return c.Redirect().To("/login")
	}

	user, err := repository.GetUserByID(uint(userID))
	if err != nil {
		return c.Redirect().To("/login")
	}

	if user.TOTPSecret != "" {
		// Already setup
		return c.Redirect().To("/login")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "NeoVault",
		AccountName: user.Username,
	})
	if err != nil {
		log.Println("Error generating TOTP secret:", err)
		return c.Status(500).SendString("Error generating TOTP")
	}

	// secret for verification

	// Generate QR code
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		log.Println("Error generating QR code:", err)
		return c.Status(500).SendString("Error generating QR code")
	}
	png.Encode(&buf, img)
	qrBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	return c.Render("auth/totp_setup", fiber.Map{
		"Title":  "Setup 2FA - Password Manager",
		"Secret": key.Secret(),
		"QRCode": template.URL("data:image/png;base64," + qrBase64),
		"UserID": user.ID,
	}, "layout")
}

// VerifyTOTPSetup verifies the first TOTP code and saves the secret
func VerifyTOTPSetup(c fiber.Ctx) error {
	userIDStr := c.FormValue("user_id")
	secret := c.FormValue("secret")
	code := c.FormValue("code")

	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		return c.Redirect().To("/login")
	}

	user, err := repository.GetUserByID(uint(userID))
	if err != nil {
		return c.Redirect().To("/login")
	}

	valid := totp.Validate(code, secret)
	if !valid {
		return c.Render("auth/totp_setup", fiber.Map{
			"Error":  "Invalid TOTP Code. Please try again.",
			"UserID": userIDStr,
		}, "layout")
	}

	user.TOTPSecret = secret
	repository.UpdateUser(user)

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

// SkipTOTP lets users bypass TOTP setup and log in without 2FA.
// A user_id form value must be provided (comes from the setup page).
func SkipTOTP(c fiber.Ctx) error {
	userIDStr := c.FormValue("user_id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil || userIDStr == "" {
		return c.Redirect().To("/login")
	}

	tokenStr, err := utils.GenerateJWT(uint(userID))
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
