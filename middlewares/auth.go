package middlewares

import (
	"github.com/jigarvarma2k20/neovault/utils"

	"github.com/gofiber/fiber/v3"
)

// Auth ensures the request carries a valid auth_token JWT.
// Sets "user_id" (uint) in Locals for downstream handlers.
func Auth(c fiber.Ctx) error {
	token := c.Cookies("auth_token")
	if token == "" {
		return c.Redirect().To("/login")
	}

	userID, err := utils.VerifyJWT(token)
	if err != nil {
		c.ClearCookie("auth_token")
		return c.Redirect().To("/login")
	}

	c.Locals("user_id", userID)
	return c.Next()
}
