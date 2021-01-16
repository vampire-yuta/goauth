package tool

type Info struct {
    dburl string
}

func (u Info) GetDBUrl() string {
     // elephantSQL の Detail に表示されている URL を記述
    return "postgres://dhucibip:UV0U7yZ6c7_qDMEJJySrPXahKZ84GoKj@arjuna.db.elephantsql.com:5432/dhucibip"
}
