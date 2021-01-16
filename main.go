package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
    "net/http"
    "strings"


	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"

	"./tool"
	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
    "github.com/lib/pq"
    "github.com/mrvdot/golang-utils"
)

type User struct {
	// 大文字だと Public 扱い
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

// JSON 形式で結果を返却
// data interface{} とすると、どのような変数の型でも引数として受け取ることができる
func responseByJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
	return
}

// dbインスタンス格納用
var db *sql.DB

func errorInResponse(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status) // 400 とか 500 などの HTTP status コードが入る
	json.NewEncoder(w).Encode(error)
	return
}

func signup(w http.ResponseWriter, r *http.Request) {
	fmt.Println("signup 関数実行")
	var user User
	var error Error

	// r.body に何が帰ってくるか確認
	fmt.Println(r.Body)

	// https://golang.org/pkg/encoding/json/#NewDecoder
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email は必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "パスワードは必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	// user に何が格納されているのか
	fmt.Println(user)

	// dump も出せる
	fmt.Println("---------------------")
	spew.Dump(user)

	// パスワードのハッシュを生成
	// https://godoc.org/golang.org/x/crypto/bcrypt#GenerateFromPassword
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("パスワード: ", user.Password)
	fmt.Println("ハッシュ化されたパスワード", hash)

	user.Password = string(hash)
	fmt.Println("コンバート後のパスワード: ", user.Password)

	sql_query := "INSERT INTO USERS(EMAIL, PASSWORD) VALUES($1, $2) RETURNING ID;"

	err = db.QueryRow(sql_query, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		error.Message = "サーバーエラー"
		errorInResponse(w, http.StatusInternalServerError, error)
		return
	}

	fmt.Println("DBインポート完了")

	// DB に登録できたらパスワードをからにしておく
	user.Password = ""
	w.Header().Set("Content-Type", "application/json")

	// JSON 形式で結果を返却
	responseByJSON(w, user)
}

// Token 作成関数
func createToken(user User) (string, error) {
	var err error

	// 鍵となる文字列(多分なんでもいい)
	secret := "secret"

	// Token を作成
	// jwt -> JSON Web Token - JSON をセキュアにやり取りするための仕様
	// jwtの構造 -> {Base64 encoded Header}.{Base64 encoded Payload}.{Signature}
	// HS254 -> 証明生成用(https://ja.wikipedia.org/wiki/JSON_Web_Token)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "__init__", // JWT の発行者が入る(文字列(__init__)は任意)
	})

	//Dumpを吐く
	spew.Dump(token)

	tokenString, err := token.SignedString([]byte(secret))

	fmt.Println("-----------------------------")
	fmt.Println("tokenString:", tokenString)

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("login 関数実行")
	var user User
    var error Error
    var jwt JWT

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email は必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "パスワードは、必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
	}

	// 追加(この位置であること)
	password := user.Password
	fmt.Println("password: ", password)

	// 認証キー(Emal)のユーザー情報をDBから取得
	row := db.QueryRow("SELECT * FROM USERS WHERE email=$1;", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows { // https://golang.org/pkg/database/sql/#pkg-variables
			error.Message = "ユーザが存在しません。"
			errorInResponse(w, http.StatusBadRequest, error)
		} else {
			log.Fatal(err)
		}
	}

	// 追加(この位置であること)
	hasedPassword := user.Password
	fmt.Println("hasedPassword: ", hasedPassword)

	err = bcrypt.CompareHashAndPassword([]byte(hasedPassword), []byte(password))

	if err != nil {
		error.Message = "無効なパスワードです。"
		errorInResponse(w, http.StatusUnauthorized, error)
		return
	}

	token, err := createToken(user)

	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseByJSON(w, jwt)
}

// 認証結果をブラウザに返却
func verifyEndpoint(w http.ResponseWriter, r *http.Request) {
    utils.ResponseJSON(w, "認証OK")
}

// verifyEndpoint のラッパーみたいなもの
func tokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        var errorObject Error

        // HTTP リクエストヘッダーを読み取る
        authHeader := r.Header.Get("Authorization")
        // Restlet Client から以下のような文字列を渡す
        // bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3Q5OUBleGFtcGxlLmNvLmpwIiwiaXNzIjoiY291cnNlIn0.7lJKe5SlUbdo2uKO_iLzzeGoxghG7SXsC3w-4qBRLvs
        bearerToken := strings.Split(authHeader, " ")
        fmt.Println("bearerToken: ", bearerToken)

        if len(bearerToken) == 2 {
            authToken := bearerToken[1]

            token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
                if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                    return nil, fmt.Errorf("エラーが発生しました。")
                }
                return []byte("secret"), nil
            })

            if error != nil {
                errorObject.Message = error.Error()
                errorInResponse(w, http.StatusUnauthorized, errorObject)
                return
            }

            if token.Valid {
               // レスポンスを返す
                next.ServeHTTP(w, r)
            } else {
                errorObject.Message = error.Error()
                errorInResponse(w, http.StatusUnauthorized, errorObject)
                return
            }
        } else {
            errorObject.Message = "Token が無効です。"
            return
        }
    })
}

func main() {
	// parmas.go から DB の URL を取得
	i := tool.Info{}

	// Convert
	// https://github.com/lib/pq/blob/master/url.go
	// "postgres://bob:secret@1.2.3.4:5432/mydb?sslmode=verify-full"
	// ->　"user=bob password=secret host=1.2.3.4 port=5432 dbname=mydb sslmode=verify-full"
	pgUrl, err := pq.ParseURL(i.GetDBUrl())

	// 戻り値に err を返してくるので、チェック
	if err != nil {
		// エラーの場合、処理を停止する
		log.Fatal()
	}

	// DB 接続
	db, err = sql.Open("postgres", pgUrl)
	if err != nil {
		log.Fatal(err)
	}

	// DB 疎通確認
	err = db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	// urls.py
	router := mux.NewRouter()

	// endpoint
	router.HandleFunc("/signup", signup).Methods("POST")
    router.HandleFunc("/login", login).Methods("POST")
    router.HandleFunc("/verify", tokenVerifyMiddleWare(verifyEndpoint)).Methods("GET")
	// service はあとで記述する

	// console に出力する
	log.Println("サーバー起動 : 8000 port で受信")

	// log.Fatal は、異常を検知すると処理の実行を止めてくれる
	log.Fatal(http.ListenAndServe(":8000", router))
}
