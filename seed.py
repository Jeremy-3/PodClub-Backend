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

        # Create channels
        channel1 = Channel(name='general', description='General discussion', owner=user1)
        channel2 = Channel(name='random', description='Random chat', owner=user2)

        # Add users to channels
        channel1.members.append(user1)
        channel1.members.append(user2)
        channel2.members.append(user1)

        # Add users and channels to the session and commit
        db.session.add_all([user1, user2, channel1, channel2])
        db.session.commit()

        # Refresh instances to get IDs
        db.session.refresh(user1)
        db.session.refresh(user2)

        # Create messages
        message1 = Message(content='Hello, everyone!', sender=user1, channel=channel1)
        message2 = Message(content='Hi Alice!', sender=user2, channel=channel1)

        # Add messages to the session and commit
        db.session.add_all([message1, message2])
        db.session.commit()

        # Create reports
        report1 = Report(user_id=user2.id, reported_user_id=user1.id, reason='Inappropriate content')

        # Add report to the session and commit
        db.session.add(report1)
        db.session.commit()

        print("Database seeded successfully!")

if __name__ == '__main__':
    seed_data()
