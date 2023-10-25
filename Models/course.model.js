const mongoose = require('mongoose');

const courseSchema = new mongoose.Schema({
  course: {
    type: String,
    required: true,
    unique: true,
  },
  duration: {
    type: String,
  },
});

module.exports = mongoose.model('Course', courseSchema);
