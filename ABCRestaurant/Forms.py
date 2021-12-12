from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, PasswordField, SubmitField, ValidationError, TextField, DecimalField
from flask_wtf import RecaptchaField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Email, InputRequired, Required
from flask_wtf import RecaptchaField




class RegisterForm(Form):
    first_name = StringField('First Name', [validators.Length(min=3, max=150), validators.DataRequired()])
    last_name = StringField('Last Name', [validators.Length(min=2, max=150), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()], choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    email = StringField('Email', [validators.DataRequired(), validators.Email("Invalid Email")])
    password = PasswordField('Password', [validators.DataRequired(),validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')
    recaptcha = RecaptchaField()
    
class UpdateForm(Form):
    first_name = StringField('First Name', [validators.Length(min=3, max=150), validators.DataRequired()])
    last_name = StringField('Last Name', [validators.Length(min=2, max=150), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()], choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    email = StringField('Email', [validators.DataRequired(), validators.Email("Invalid Email")])
    password = PasswordField('Password', [validators.DataRequired(),validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')    


class UpdateForm(Form):
    first_name = StringField('First Name', [validators.Length(min=3, max=150), validators.DataRequired()])
    last_name = StringField('Last Name', [validators.Length(min=2, max=150), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()], choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    email = StringField('Email', [validators.DataRequired(), validators.Email("Invalid Email")])
    password = PasswordField('Password', [validators.DataRequired(),validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')


class ContactUsForm(Form):
    first_name = StringField('First Name', [validators.DataRequired("Please enter your first name")])
    last_name = StringField('Last Name', [validators.DataRequired("Please enter your last name")])
    email = StringField('Email', [validators.DataRequired("Please enter a valid email address"), validators.Email()])
    subject = StringField('Subject', [validators.DataRequired("Please enter a subject")])
    enquiry = TextAreaField("Enquiry", [validators.DataRequired("Please enter an enquiry")])


class ReviewForm(Form):
    rating = RadioField('Rating', choices=[('5', '5'), ('4', '4'), ('3', '3'), ('2', '2'), ('1', '1')],  default='1', validators=[DataRequired()])
    title = StringField('Title', [validators.DataRequired("Please enter a title")])
    review = TextAreaField("Review", [validators.DataRequired("Please enter a review")])

class updateReviewForm(Form):
    updated_rating = RadioField('Rating', choices=[('5', '5'), ('4', '4'), ('3', '3'), ('2', '2'), ('1', '1')])
    updated_title = StringField('Title', [validators.DataRequired("Please enter a title")])
    updated_review = TextAreaField("Review", [validators.DataRequired("Please enter a review")])

class reportForm(Form):
    value = SelectField('', choices=[('Review Ratings','Review Ratings'), ('Customer Transaction History', 'Customer Transaction History'), ('Total Amount', 'Total Amount'), ('Payment Method', 'Payment Method'), ('Logs', 'Logs')], default='Customer Transaction History', id="select")

class FAQSearchForm(Form):
    search = StringField('')

class createProductForm(Form):
    product_name = StringField('Product Name', [validators.DataRequired("Please enter Product Name")])
    product_price = DecimalField('Product Price', places=2)

class ForgetPasswordForm(Form):
    email = StringField('Email', [validators.DataRequired("Please enter a registered email address"), validators.Email()])
