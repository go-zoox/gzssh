package oauthqrcode

import (
	"errors"
	"fmt"

	"github.com/go-zoox/fetch"
	"github.com/go-zoox/logger"
)

type LoginInf interface {
	// GenerateUUID() error
	GetStatus() (ok bool, err error)
	GetToken() error
	GetUser() error
	//
	GetQRCodeURL() chan string
	GetQRCodeUUID() string
	GetQRCodeStatus() string
	//
	GetCurrentUser() *User
	GetAccessToken() (string, error)
}

func NewLogin(QRCodeRequestServer, ClientID, RedirectURI string, accessToken ...string) LoginInf {
	accessTokenX := ""
	if len(accessToken) > 0 && accessToken[0] != "" {
		accessTokenX = accessToken[0]
	}

	return &login{
		QRCodeRequestServer: QRCodeRequestServer,
		ClientID:            ClientID,
		RedirectURI:         RedirectURI,
		accessToken:         accessTokenX,
		//
		url: make(chan string),
	}
}

type login struct {
	QRCodeRequestServer string
	//
	ClientID    string
	RedirectURI string
	//
	uuid string
	url  chan string
	// INIT => SCAN | CONFIRM |
	status string
	//
	authorizationCode string
	//
	accessToken string
	//
	user *User
}

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
}

// func Login(QRCodeRequestServer, ClientID, RedirectURI string) (accessToken string, err error) {
// 	state := NewLogin(QRCodeRequestServer, ClientID, RedirectURI)

// 	if err := state.GenerateUUID(); err != nil {
// 		return "", err
// 	}

// 	done := make(chan bool)

// 	go func() {
// 		for {
// 			if ok, err := state.GetStatus(); err != nil {
// 				log.Fatalf("failed to get status: %v", err)
// 			} else if ok {
// 				// fmt.Println("login success")
// 				done <- true
// 				break
// 			} else {
// 				// fmt.Printf("waiting for login(status: %s) ...\n", state.GetQRCodeStatus())
// 				time.Sleep(3000)
// 			}
// 		}
// 	}()

// 	state.GetQRCodeURL()

// 	for {
// 		select {
// 		case <-done:
// 			if err := state.GetToken(); err != nil {
// 				return "", fmt.Errorf("failed to get token: %v", err)
// 			}
// 			if err := state.GetUser(); err != nil {
// 				return "", fmt.Errorf("failed to get user: %v", err)
// 			}

// 			if err := SetAuthToken(state.GetAccessToken()); err != nil {
// 				return "", fmt.Errorf("failed to set auth token: %v", err)
// 			}

// 			// clear screen
// 			clear := exec.Command("clear")
// 			clear.Stdout = os.Stdout
// 			clear.Run()

// 			logger.Infof("welcome %s (email: %s)", state.GetCurrentUser().Nickname, state.GetCurrentUser().Email)
// 			// logger.Info("token: %s", state.GetAccessToken())
// 			return state.GetAccessToken(), nil
// 		}
// 	}
// }

func IsLogin(server, accessToken string) bool {
	// state := NewLogin(accessToken)
	// if err := state.GetUser(); err != nil {
	// 	return false
	// }

	// return true
	client := New(&ClientConfig{
		Server: server,
		Token:  accessToken,
	})

	if _, err := client.User().Get(); err != nil {
		// fmt.Println("Error getting user: ", err)
		return false
	}

	return true
}

// GET https://login.zcorky.com/api/qrcode/device/uuid?client_id=bce050f54133ecf94667a47ad10367b9&redirect_uri=https://eunomia.example.com:2443/login/doreamon/callback&state=xxx&scope=xxx&response_type=code
func (l *login) GenerateUUID() (err error) {
	response, err := fetch.Get(fmt.Sprintf("%s/api/qrcode/device/uuid", l.QRCodeRequestServer), &fetch.Config{
		Headers: fetch.Headers{
			"Accept": "application/json",
		},
		Query: fetch.Query{
			"client_id":     l.ClientID,
			"redirect_uri":  l.RedirectURI,
			"response_type": "code",
			"state":         "_",
			"scope":         "qrcode",
		},
	})
	if err != nil {
		return fmt.Errorf("failed to get uuid: err: %v", err)
	}

	l.uuid = response.Get("uuid").String()
	url := response.Get("url").String()
	if url == "" {
		return fmt.Errorf("qrcode url is empty, maybe qrcode url internal error, no detail @TODO (response: %s)", response.String())
	}

	// l.url
	l.url <- url
	return
	// if l.uuid == "" {
	// 	fmt.Println(response.String())
	// 	return fmt.Errorf("uuid is empty")
	// }
	// // if l.url
	// return l.url == "" {
	// 	return fmt.Errorf("url is empty")
	// }

	// return
}

// GET https://login.zcorky.com/api/qrcode/device/status?uuid=78f10664-ff58-4a6b-a10c-9ad59440d75f
func (l *login) GetStatus() (ok bool, err error) {
	response, err := fetch.Get(fmt.Sprintf("%s/api/qrcode/device/status?uuid=%s", l.QRCodeRequestServer, l.uuid), &fetch.Config{
		Headers: fetch.Headers{
			"Accept": "application/json",
		},
	})
	if err != nil {
		return false, fmt.Errorf("failed to get status: %v", err)
	}

	code := response.Get("code").Int()
	if code != 0 {
		message := response.Get("message").String()
		return false, fmt.Errorf("failed to get status: code: %d, message: %s", code, message)
	}

	status := response.Get("status").String()
	authorizationCode := response.Get("authorization_code").String()
	if status != "" {
		l.status = status
	}

	if authorizationCode != "" {
		l.authorizationCode = authorizationCode
		return true, nil
	}

	return false, nil
}

// POST https://login.zcorky.com/api/qrcode/device/token
//
//	{
//		"uuid": "ee2c9622-0bdd-4027-a4d3-39dbe0d6f67a",
//		"code": "2ea1f55eb199d09603ed93dc3a2f8a2d1798d9ed"
//	}
func (l *login) GetToken() error {
	response, err := fetch.Post(fmt.Sprintf("%s/api/qrcode/device/token", l.QRCodeRequestServer), &fetch.Config{
		Headers: fetch.Headers{
			"Accept":       "application/json",
			"Content-Type": "application/json",
		},
		Body: map[string]string{
			"uuid": l.uuid,
			"code": l.authorizationCode,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	accessToken := response.Get("access_token").String()
	if accessToken == "" {
		return fmt.Errorf("access_token is empty")
	}

	l.accessToken = accessToken
	return nil
}

// GET https://login.zcorky.com/api/qrcode/device/user
//
//	Authorization: Bearer qrcode_access_1998c11e499ddb375b1c3b7a4a
func (l *login) GetUser() (err error) {
	response, err := fetch.Get(fmt.Sprintf("%s/api/qrcode/device/user", l.QRCodeRequestServer), &fetch.Config{
		Headers: fetch.Headers{
			"Accept":        "application/json",
			"Authorization": fmt.Sprintf("Bearer %s", l.accessToken),
		},
	})
	if err != nil {
		return
	}

	var user User
	if err = response.UnmarshalJSON(&user); err != nil {
		return fmt.Errorf("failed to parse user: %v", err)
	}

	l.user = &user
	return
}

// //////////////////////////////////////////////////////////////////////////////
func (l *login) GetQRCodeURL() chan string {
	go func() {
		if err := l.GenerateUUID(); err != nil {
			// @TODO failed to generate uuid
			logger.Errorf("GenerateUUID error: %v", err)
			return
		}
	}()

	return l.url
}

func (l *login) GetQRCodeUUID() string {
	return l.uuid
}

func (l *login) GetQRCodeStatus() string {
	return l.status
}

func (l *login) GetCurrentUser() *User {
	return l.user
}

func (l *login) GetAccessToken() (string, error) {
	if l.accessToken == "" {
		return "", errors.New("cannot get access token")
	}

	return l.accessToken, nil
}
