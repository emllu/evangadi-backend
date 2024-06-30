import { connection } from "../../config/db.js";
//question, catagory,questionDescription, id
const questionService = {
  addNewQuestion: (data, callback) => {
    // console.log(data);
    connection.query(
      `INSERT INTO question (question, question_description, category, user_id, inserted_datetime)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      [data.question, data.questionDescription, data.catagory, data.user_id],
      (err, result) => {
        if (err) {
          return callback(err);
        }
        return callback(null, result);
      }
    );
  },
  getAllQuestions: (callback) => {
    connection.query(
      `SELECT * FROM question ORDER BY inserted_datetime DESC`,
      [],
      (err, result) => {
        if (err) {
          return callback(err);
        }
        return callback(null, result);
      }
    );
  },
  questionById: (id, callback) => {
    //id is postId
    connection.query(
      `SELECT * FROM question WHERE question_id = ?`,
      [id],
      (err, result) => {
        if (err) {
          return callback(err);
        }
        return callback(null, result[0]);
      }
    );
  },
};

export default questionService;
