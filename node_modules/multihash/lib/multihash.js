/**
 * `MultiHash` constructor.
 *
 * @api public
 */
function MultiHash() {
  this._hash = {};
  this.__defineGetter__('length', this._length);
}

/**
 * Array of keys.
 *
 * @return {Array}
 * @api public
 */
MultiHash.prototype.keys = function() {
  return Object.keys(this._hash);
};

/**
 * Test if `key` is set.
 *
 * @param {String} key
 * @return {Boolean} _true_ if set, _false_ otherwise
 * @api public
 */
MultiHash.prototype.has = function(key) {
  return (this._hash[key] !== undefined);
};

/**
 * Number of values set for `key`.
 *
 * @param {String} key
 * @return {Number}
 * @api public
 */
MultiHash.prototype.count = function(key) {
  return this.has(key) ? this._hash[key].length : 0;
};

/**
 * Array of values for `key`.
 *
 * @param {String} key
 * @return {Array}
 * @api public
 */
MultiHash.prototype.values = function(key) {
  return this.has(key) ? this._hash[key] : [];
};

/**
 * Put `value` for `key`.
 *
 * Multi-hashes can contain multiple values for the same key.  Putting a value
 * to a key will add a value, rather than replace an existing value.
 *
 * @param {String} key
 * @param {Mixed} value
 * @api public
 */
MultiHash.prototype.put = function(key, value) {
  if (this.has(key)) {
    this._hash[key].push(value);
  } else {
    this._hash[key] = [ value ];
  }
};

/**
 * Add keys and values of `obj`.
 *
 * @param {Object} obj
 * @param {Mixed} value
 * @api public
 */
MultiHash.prototype.add = function(obj) {
  if (!obj) { return; }
  var self = this;
  Object.keys(obj).forEach(function(key) {
    self.put(key, obj[key]);
  });
};

/**
 * Delete `key`.
 *
 * @param {String} key
 * @api public
 */
MultiHash.prototype.del = function(key) {
  delete this._hash[key];
};

/**
 * Executes provided `fn` once per key-value pair.
 *
 * Options:
 *   - `flatten`  iterate over a single (most recent) value per key, defaults to _false_
 *
 * @param {Function} fn
 * @param {Object} options
 * @api public
 */
MultiHash.prototype.forEach = function(fn, options) {
  options = options || {};
  
  var self = this;
  Object.keys(this._hash).forEach(function(key) {
    if (options.flatten) {
      var array = self._hash[key];
      fn(key, array[array.length - 1]);
    } else {
      self._hash[key].forEach(function(value) {
        fn(key, value);
      });
    }
  });
};

/**
 * Number of keys in the multi-hash.
 *
 * @return {Number}
 * @api private
 */
MultiHash.prototype._length = function() {
  return Object.keys(this._hash).length;
};


/**
 * Expose `MultiHash`.
 */
module.exports = MultiHash;
