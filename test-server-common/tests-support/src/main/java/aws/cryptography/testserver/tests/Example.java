package aws.cryptography.testserver.tests;

/** One test input and a short name that says what makes it valid or invalid. */
public record Example<T>(String name, T value) {
    @Override
    public String toString() {
        return name;
    }
}
