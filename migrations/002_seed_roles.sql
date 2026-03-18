INSERT INTO roles (code, name, description, is_default, is_privileged, is_support)
VALUES
    ('student', 'Student', 'Learner role for course participation and progress tracking', TRUE, FALSE, FALSE),
    ('teacher', 'Teacher', 'Teaching role for creating content and assessing learners', FALSE, FALSE, FALSE),
    ('manager', 'Manager', 'Operational role for managing educational workflows and users', FALSE, TRUE, TRUE),
    ('admin', 'Administrator', 'System role with full access to security and role administration', FALSE, TRUE, FALSE)
ON CONFLICT (code) DO UPDATE
SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    is_default = EXCLUDED.is_default,
    is_privileged = EXCLUDED.is_privileged,
    is_support = EXCLUDED.is_support;

INSERT INTO user_roles (user_id, role_id, assigned_by, assigned_at)
SELECT u.id, r.id, NULL, NOW()
FROM users u
INNER JOIN roles r ON r.code = 'student'
LEFT JOIN user_roles ur ON ur.user_id = u.id AND ur.role_id = r.id
WHERE ur.user_id IS NULL;
