-- schema.sql

DROP TABLE IF EXISTS notification;
DROP TABLE IF EXISTS todo;
DROP TABLE IF EXISTS user;

CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE todo (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    due_date DATETIME,
    is_completed BOOLEAN NOT NULL DEFAULT 0, -- 0 for False, 1 for True
    priority TEXT DEFAULT 'Medium', -- 'High', 'Medium', 'Low'
    user_id INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user (id)
);

CREATE TABLE notification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    todo_id INTEGER, -- Can be NULL if notification is not task-specific
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT 0, -- 0 for False, 1 for True
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notification_type TEXT DEFAULT 'general', -- e.g., 'due_today', 'overdue'
    FOREIGN KEY (user_id) REFERENCES user (id),
    FOREIGN KEY (todo_id) REFERENCES todo (id)
);

-- Optional: Triggers for updated_at in todo table (SQLite specific)
CREATE TRIGGER set_todo_updated_at
AFTER UPDATE ON todo
FOR EACH ROW
BEGIN
    UPDATE todo SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
END;