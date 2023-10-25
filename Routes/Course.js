const express = require('express');
const router = express.Router();
const CourseModel = require('../Models/course.model');

// Create a new course
router.post('/create', async (req, res) => {
    try {
      const { course, duration } = req.body;
      const existingCourse = await CourseModel.findOne({ course });
  
      if (existingCourse) {
        return res.status(400).json({ error: 'Course already exists' });
      }
  
      const post = new CourseModel({ course, duration });
      await post.save();
  
      return res.status(200).json({ message: 'Successfully created' });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
  

router.get('/courses', async (req, res) => {
  try {
    const courses = await CourseModel.find();
    res.status(200).json(courses);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
