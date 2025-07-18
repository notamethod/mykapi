package com.notamethod.mkcore.utils;


import java.io.*;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.InvalidPropertiesFormatException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;

/**
 * This class provides an alternative to the JDK's {@link Properties} class. It fixes the design flaw of using
 * inheritance over composition, while keeping up the same APIs as the original class. Keys and values are
 * guaranteed to be of type {@link String}.
 * <p/>
 * This class is not synchronized, contrary to the original implementation.
 * <p/>
 * As additional functionality, this class keeps its properties in a well-defined order. By default, the order
 * is the one in which the individual properties have been added, either through explicit API calls or through
 * reading them top-to-bottom from a properties file.
 * <p/>
 * Also, an optional flag can be set to omit the comment that contains the current date when storing the
 * properties to a properties file.
 * <p/>
 * Currently, this class does not support the concept of default properties, contrary to the original implementation.
 * <p/>
 * <strong>Note that this implementation is not synchronized.</strong> If multiple threads access ordered
 * properties concurrently, and at least one of the threads modifies the ordered properties structurally, it
 * <em>must</em> be synchronized externally. This is typically accomplished by synchronizing on some object
 * that naturally encapsulates the properties.
 * <p/>
 * Note that the actual (and quite complex) logic of parsing and storing properties from and to a stream
 * is delegated to the {@link Properties} class from the JDK.
 *
 * @see Properties
 */
@SuppressWarnings({"MismatchedQueryAndUpdateOfCollection", "RedundantSuppression"})
public final class OrderedProperties implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private transient Map<String, String> properties;
    private transient boolean suppressDate;

    /**
     * Creates a new instance that will keep the properties in the order they have been added. Other than
     * the ordering of the keys, this instance behaves like an instance of the {@link Properties} class.
     */
    public OrderedProperties() {
        this(new LinkedHashMap<>(), false);
    }

    private OrderedProperties(Map<String, String> properties, boolean suppressDate) {
        this.properties = properties;
        this.suppressDate = suppressDate;
    }

    /**
     * See {@link Properties#getProperty(String)}.
     */
    public String getProperty(String key) {
        return properties.get(key);
    }

    /**
     * See {@link Properties#getProperty(String, String)}.
     */
    public String getProperty(String key, String defaultValue) {
        String value = properties.get(key);
        return (value == null) ? defaultValue : value;
    }

    /**
     * See {@link Properties#setProperty(String, String)}.
     */
    public String setProperty(String key, String value) {
        return properties.put(key, value);
    }

    /**
     * Removes the property with the specified key, if it is present. Returns
     * the value of the property, or <tt>null</tt> if there was no property with
     * the specified key.
     *
     * @param key the key of the property to remove
     * @return the previous value of the property, or <tt>null</tt> if there was no property with the specified key
     */
    public String removeProperty(String key) {
        return properties.remove(key);
    }

    /**
     * Returns <tt>true</tt> if there is a property with the specified key.
     *
     * @param key the key whose presence is to be tested
     */
    public boolean containsProperty(String key) {
        return properties.containsKey(key);
    }

    /**
     * See {@link Properties#size()}.
     */
    public int size() {
        return properties.size();
    }

    /**
     * See {@link Properties#isEmpty()}.
     */
    public boolean isEmpty() {
        return properties.isEmpty();
    }

    /**
     * See {@link Properties#propertyNames()}.
     */
    public Enumeration<String> propertyNames() {
        return new Vector<>(properties.keySet()).elements();
    }

    /**
     * See {@link Properties#stringPropertyNames()}.
     */
    public Set<String> stringPropertyNames() {
        return new LinkedHashSet<>(properties.keySet());
    }

    /**
     * See {@link Properties#entrySet()}.
     */
    public Set<Map.Entry<String, String>> entrySet() {
        return new LinkedHashSet<>(properties.entrySet());
    }

    /**
     * See {@link Properties#load(InputStream)}.
     */
    public void load(InputStream stream) throws IOException {
        CustomProperties customProperties = new CustomProperties(this.properties);
        customProperties.load(stream);
    }

    /**
     * See {@link Properties#load(Reader)}.
     */
    public void load(Reader reader) throws IOException {
        CustomProperties customProperties = new CustomProperties(this.properties);
        customProperties.load(reader);
    }

    /**
     * See {@link Properties#loadFromXML(InputStream)}.
     */
    @SuppressWarnings("DuplicateThrows")
    public void loadFromXML(InputStream stream) throws IOException, InvalidPropertiesFormatException {
        CustomProperties customProperties = new CustomProperties(this.properties);
        customProperties.loadFromXML(stream);
    }

    /**
     * See {@link Properties#store(OutputStream, String)}.
     */
    public void store(OutputStream stream, String comments) throws IOException {
        CustomProperties customProperties = new CustomProperties(this.properties);
        if (suppressDate) {
            customProperties.store(new DateSuppressingPropertiesBufferedWriter(new OutputStreamWriter(stream, "8859_1")), comments);
        } else {
            customProperties.store(stream, comments);
        }
    }

    /**
     * See {@link Properties#store(Writer, String)}.
     */
    public void store(Writer writer, String comments) throws IOException {
        CustomProperties customProperties = new CustomProperties(this.properties);
        if (suppressDate) {
            customProperties.store(new DateSuppressingPropertiesBufferedWriter(writer), comments);
        } else {
            customProperties.store(writer, comments);
        }
    }

    /**
     * See {@link Properties#storeToXML(OutputStream, String)}.
     */
    public void storeToXML(OutputStream stream, String comment) throws IOException {
        CustomProperties customProperties = new CustomProperties(this.properties);
        customProperties.storeToXML(stream, comment);
    }

    /**
     * See {@link Properties#storeToXML(OutputStream, String, String)}.
     */
    public void storeToXML(OutputStream stream, String comment, String encoding) throws IOException {
        CustomProperties customProperties = new CustomProperties(this.properties);
        customProperties.storeToXML(stream, comment, encoding);
    }

    /**
     * See {@link Properties#list(PrintStream)}.
     */
    public void list(PrintStream stream) {
        CustomProperties customProperties = new CustomProperties(this.properties);
        customProperties.list(stream);
    }

    /**
     * See {@link Properties#list(PrintWriter)}.
     */
    public void list(PrintWriter writer) {
        CustomProperties customProperties = new CustomProperties(this.properties);
        customProperties.list(writer);
    }

    /**
     * Convert this instance to a {@link Properties} instance.
     *
     * @return the {@link Properties} instance
     */
    public Properties toJdkProperties() {
        Properties jdkProperties = new Properties();
        for (Map.Entry<String, String> entry : this.entrySet()) {
            jdkProperties.put(entry.getKey(), entry.getValue());
        }
        return jdkProperties;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }

        if (other == null || getClass() != other.getClass()) {
            return false;
        }

        OrderedProperties that = (OrderedProperties) other;
        return Arrays.equals(properties.entrySet().toArray(), that.properties.entrySet().toArray());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(properties.entrySet().toArray());
    }

    @SuppressWarnings("squid:S2118")
    private void writeObject(ObjectOutputStream stream) throws IOException {
        stream.defaultWriteObject();
        stream.writeObject(properties);
        stream.writeBoolean(suppressDate);
    }

    @SuppressWarnings("unchecked")
    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();
        properties = (Map<String, String>) stream.readObject();
        suppressDate = stream.readBoolean();
    }

    private void readObjectNoData() throws InvalidObjectException {
        throw new InvalidObjectException("Stream data required");
    }

    /**
     * See {@link Properties#toString()}.
     */
    @Override
    public String toString() {
        return properties.toString();
    }

    /**
     * Creates a new instance that will have both the same property entries and
     * the same behavior as the given source.
     * <p/>
     * Note that the source instance and the copy instance will share the same
     * comparator instance if a custom ordering had been configured on the source.
     *
     * @param source the source to copy from
     * @return the copy
     */
    public static OrderedProperties copyOf(OrderedProperties source) {
        // create a copy that has the same behaviour
        OrderedPropertiesBuilder builder = new OrderedPropertiesBuilder();
        builder.withSuppressDateInComment(source.suppressDate);
        if (source.properties instanceof TreeMap) {
            builder.withOrdering(((TreeMap<String, String>) source.properties).comparator());
        }
        OrderedProperties result = builder.build();

        // copy the properties from the source to the target
        for (Map.Entry<String, String> entry : source.entrySet()) {
            result.setProperty(entry.getKey(), entry.getValue());
        }
        return result;
    }

    /**
     * Builder for {@link OrderedProperties} instances.
     */
    public static final class OrderedPropertiesBuilder {

        private Comparator<? super String> comparator;
        private boolean suppressDate;

        /**
         * Use a custom ordering of the keys.
         *
         * @param comparator the ordering to apply on the keys
         * @return the builder
         */
        public OrderedPropertiesBuilder withOrdering(Comparator<? super String> comparator) {
            this.comparator = comparator;
            return this;
        }

        /**
         * Suppress the comment that contains the current date when storing the properties.
         *
         * @param suppressDate whether to suppress the comment that contains the current date
         * @return the builder
         */
        public OrderedPropertiesBuilder withSuppressDateInComment(boolean suppressDate) {
            this.suppressDate = suppressDate;
            return this;
        }

        /**
         * Builds a new {@link OrderedProperties} instance.
         *
         * @return the new instance
         */
        public OrderedProperties build() {
            Map<String, String> properties = (this.comparator != null) ?
                    new TreeMap<>(comparator) :
                    new LinkedHashMap<>();
            return new OrderedProperties(properties, suppressDate);
        }

    }

    /**
     * Custom {@link Properties} that delegates reading, writing, and enumerating properties to the
     * backing {@link OrderedProperties} instance's properties.
     */
    private static final class CustomProperties extends Properties {

        private final Map<String, String> targetProperties;

        private CustomProperties(Map<String, String> targetProperties) {
            this.targetProperties = targetProperties;
        }

        @Override
        public Object get(Object key) {
            return targetProperties.get(key);
        }

        @Override
        public synchronized Object put(Object key, Object value) {
            return targetProperties.put((String) key, (String) value);
        }

        @Override
        public String getProperty(String key) {
            return targetProperties.get(key);
        }

        @Override
        public Enumeration<Object> keys() {
            return new Vector<Object>(targetProperties.keySet()).elements();
        }

        @SuppressWarnings("NullableProblems")
        @Override
        public Set<Object> keySet() {
            return new LinkedHashSet<>(targetProperties.keySet());
        }

    }

    /**
     * Custom {@link BufferedWriter} for storing properties that will write all leading lines of comments except
     * the last comment line. Using the JDK Properties class to store properties, the last comment
     * line always contains the current date which is what we want to filter out.
     */
    private static final class DateSuppressingPropertiesBufferedWriter extends BufferedWriter {

        private final String LINE_SEPARATOR = System.getProperty("line.separator");

        private StringBuilder currentComment;
        private String previousComment;

        private DateSuppressingPropertiesBufferedWriter(Writer out) {
            super(out);
        }

        @SuppressWarnings("NullableProblems")
        @Override
        public void write(String string) throws IOException {
            if (currentComment != null) {
                currentComment.append(string);
                if (string.endsWith(LINE_SEPARATOR)) {
                    if (previousComment != null) {
                        super.write(previousComment);
                    }

                    previousComment = currentComment.toString();
                    currentComment = null;
                }
            } else if (string.startsWith("#")) {
                currentComment = new StringBuilder(string);
            } else {
                super.write(string);
            }
        }

    }

}