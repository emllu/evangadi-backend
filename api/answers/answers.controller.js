import { connection } from "../../config/db.js";
import answersService from "./answers.service.js";


const answersController = {
  getAnswersById: (req, res) => {
    let id = req.params.id[1];
    answersService.answersById(id, (err, results) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ msg: "database connection error" });
      }
      if (!results) {
        return res.status(400).json({ msg: "Record not found" });
      }
      return res.status(200).json({ data: results });
    });
  },
  newAnswers: (req, res) => {
    const { answer, user_id, question_id } = req.body;
    if (!answer || !user_id || !question_id) {
      return res.status(400).json({ msg: 'Not all fields have been provided!' });
    }

    answersService.newAnswers(req.body, (err, results) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ msg: "database connection error 9999" });
      }
      if (!results) {
        return res.status(400).json({ msg: "Record not found 888" });
      }
      return res.status(200).json({ data: results, msg: 'Your answer has been successfully added.' });
    });
  }
};

export default answersController;
