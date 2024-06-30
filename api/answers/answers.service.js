import { connection } from '../../config/db.js'

const answersService = {
    answersById:(id, callback) => {
        //id is postId
        connection.query(`SELECT registration.user_name, answer.answer_id, answer.answer, answer.answered_date, profile.image_url
        FROM registration
        JOIN answer ON registration.user_id = answer.user_id
        JOIN profile ON registration.user_id = profile.user_id
        WHERE answer.question_id = ?  ORDER BY answered_date DESC;`, [id], (err, result) => {
            if (err) {
                return callback(err);
            }
            return callback(null, result);
        })
    },
    
    newAnswers: (data, callback) => { 
        connection.query(`INSERT INTO answer (answer, user_id, question_id,answered_date) values (?,?,?,now());`,
            [    data.answer,
                 data.user_id,
                data.question_id
            ],
            (err, result) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, result);
            }
        )
    }
}

export default answersService;