package domain

import (
	"github.com/google/uuid"
	"time"
)

// todo: перенести в отдельную таблицу

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	Roles        []Role
	IsActive     bool
	CreatedAt    time.Time
}


{
	"id":"yeyrwi2894955",
	"name":"Aliya",
	"roles":[
{
"code":"admin",
"value":"Администратор"
},
{
"code":"student",
"value":"Студент"
},
	]
}

user -> информация выходит по юзеру (user_id) +
user_roles (user_id) -> какие у него роли (role_id multiple)
roles -> in (role1_id,role2_id) инфа по ролям
user.Roles=roles(from db)


user_id, roles[role_id_1,role_id_2]
validate что эти айдишники в бд существуют и юзер и роли
select * from roles where id in (qwet2475858t,32455yutit)
*/
