package truelayer.signing

internal data class HeaderName(val name: String) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HeaderName

        if (name.lowercase() != other.name.lowercase()) return false

        return true
    }

    override fun hashCode(): Int {
        return name.lowercase().hashCode()
    }
}