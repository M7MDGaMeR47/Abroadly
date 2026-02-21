require('dotenv').config();
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

async function testEmail() {
    console.log(`Attempting to login to Gmail as: ${process.env.EMAIL_USER}`);
    console.log(`Password length: ${process.env.EMAIL_PASS ? process.env.EMAIL_PASS.length : 'MISSING'}`);

    try {
        await transporter.verify();
        console.log('✅ SMTP Connection successful! Credentials are correct.');

        const info = await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: 'Abroadly - Test Email',
            text: 'This is a test email from your local server. If you see this, Nodemailer is working perfectly.'
        });

        console.log('✅ Test email sent to yourself successfully!', info.messageId);
    } catch (error) {
        console.error('❌ Connection or sending failed. Detailed error:');
        console.error(error);
    }
}

testEmail();
