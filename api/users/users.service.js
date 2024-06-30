import { connection} from '../../config/db.js'

const userService = {
    //data comes form the user controller
    register: (data, callback) => {
        connection.query(`INSERT INTO registration(user_name,user_email,user_password)VALUES(?,?,?)`,
            [
                data.userName,
                data.email,
                data.password
            ],
            (err, result) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, result);
            }
        );
        //query select user using email to get user_id
    },
    changepass: (data, callback) => {
        console.log(data.new_password)
    

        connection.query(`UPDATE registration SET user_password = ? WHERE user_email = ?`,
            [
                data.new_password
                , data.email
            ],
            (err, result) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, result);
            }
        );
        //query select user using email to get user_id
    },

    profile: (data, callback) => {
        connection.query(`INSERT INTO profile(user_id,first_name,middle_name,last_name,other_name)VALUES(?,?,?,?,?)`,
            [
                data.userId,
                data.firstName,
                data.middleName,
                data.lastName,
                data.otherName,
                // data.imageUrl,
            ],
            (err, result) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, result);
            }
        );
    },
    getAllUsers: (callback) => {
        connection.query(`SELECT user_id,user_name,user_email FROM registration`,  (err, result) => {
            if (err) {
                return callback(err);
            }
            return callback(null, result);
        })
    },
    userById: (id, callback) => {
        connection.query(`SELECT registration.user_id,user_name,user_email,first_name,middle_name,last_name,other_name,image_url FROM registration LEFT JOIN profile ON registration.user_id = profile.user_id WHERE registration.user_id = ?`, [id], (err, result) => {
            if (err) {
                return callback(err);
            }
            return callback(null, result[0]);
        })
    },
    getUserByEmail: (email, callback) => {
        connection.query(`SELECT * FROM registration WHERE user_email = ?`, [email], (err, result) => {
            if (err) {
                return callback(err);
            }
            return callback(null, result[0]);
        })
    },
    getUserByUsername: (username, callback) => {
        connection.query(`SELECT * FROM registration WHERE user_name = ?`, [username], (err, result) => {
            if (err) {
                return callback(err);
            }
            return callback(null, result[0]);
        })
    }
}

export default userService;