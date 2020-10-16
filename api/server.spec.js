const supertest = require('supertest');

const server = require('./server.js');
const db = require('../database/dbConfig.js/');

const testUser = { username: 'test', password: 'test' };

describe('server.js', () => {
  describe('get request for jokes', () => {
    it('should return a status of 400 when not logged in', () => {
      return supertest(server).get('/api/jokes')
        .then(res => {
          expect(res.status).toBe(401);
        })
    });

    it('should return json of joke', () => {
      return supertest(server).get('/api/jokes')
        .then(res => {
          expect(res.type).toBe('application/json');
        })
    });
  });

  describe('registering a new user', () => {
    it('should return status code 201 when adding a new user', async () => {
      await db('users').truncate();

      return supertest(server).post('/api/auth/register')
        .send(testUser)
        .then(res => {
          expect(res.status).toBe(201);
        })
    });

    it('should return status code 500 when adding invalid user', async () => {
      return supertest(server).post('/api/auth/register')
        .send({user: 'bob', pass: 'joe'})
        .then(res => {
          expect(res.status).toBe(400);
        })
    });
  });

  describe('login with user', () => {
    it('should return 200 with test user', () => {
      return supertest(server).post('/api/auth/login')
        .send(testUser)
        .then(res => {
          expect(res.status).toBe(200);
        })
    })

    it('should return 401 with invalid user', () => {
      return supertest(server).post('/api/auth/login')
        .send({ username: 'not', password: 'working' })
        .then(res => {
          expect(res.status).toBe(401);
        })
    })
  })
})