from app import app
from models import db, User, Channel, Message, Report

def seed_data():
    with app.app_context():
        # Clear existing data
        db.drop_all()
        db.create_all()

        # Create users
        user1 = User(username='alice', email='alice@example.com', role='user')
        user1.set_password('password123')
        user2 = User(username='bob', email='bob@example.com', role='admin')
        user2.set_password('password123')
        user3 = User(username='charlie', email='charlie@example.com', role='user')
        user3.set_password('password123')
        user4 = User(username='dave', email='dave@example.com', role='user')
        user4.set_password('password123')
        user5 = User(username='eve', email='eve@example.com', role='user')
        user5.set_password('password123')

        # Create channels
        channel1 = Channel(name='general', description='General discussion', owner=user1)
        channel2 = Channel(name='random', description='Random chat', owner=user2)
        channel3 = Channel(name='cars', description='Discussion about cars', owner=user3)
        channel4 = Channel(name='foodies', description='Food lovers unite', owner=user4)
        channel5 = Channel(name='travels', description='Travel tips and experiences', owner=user5)

        # Add users to channels
        channel1.members.extend([user1, user2, user3, user4, user5])
        channel2.members.extend([user1, user2, user3])
        channel3.members.extend([user1, user3, user4])
        channel4.members.extend([user2, user4, user5])
        channel5.members.extend([user1, user3, user5])

        # Add users and channels to the session and commit
        db.session.add_all([user1, user2, user3, user4, user5, channel1, channel2, channel3, channel4, channel5])
        db.session.commit()

        # Refresh instances to get IDs
        db.session.refresh(user1)
        db.session.refresh(user2)
        db.session.refresh(user3)
        db.session.refresh(user4)
        db.session.refresh(user5)

        # Create messages
        message1 = Message(content='Hello, everyone!', sender=user1, channel=channel1)
        message2 = Message(content='Hi Alice!', sender=user2, channel=channel1)
        message3 = Message(content='Check out this cool car!', sender=user3, channel=channel3)
        message4 = Message(content='What’s for dinner tonight?', sender=user4, channel=channel4)
        message5 = Message(content='Just came back from an amazing trip!', sender=user5, channel=channel5)

        # Add messages to the session and commit
        db.session.add_all([message1, message2, message3, message4, message5])
        db.session.commit()

        # Create reports
        report1 = Report(user_id=user2.id, reported_user_id=user1.id, reason='Inappropriate content')
        report2 = Report(user_id=user4.id, reported_user_id=user3.id, reason='Sending spam messages')
        report3 = Report(user_id=user5.id, reported_user_id=user2.id, reason='Harassment and inappropriate behavior')

        # Add reports to the session and commit
        db.session.add_all([report1, report2, report3])
        db.session.commit()

        print("Database seeded successfully!")

if __name__ == '__main__':
    seed_data()
